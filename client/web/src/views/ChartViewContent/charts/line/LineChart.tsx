import React, { ReactElement, useCallback, useMemo, useState, MouseEvent, useRef } from 'react'
import classnames from 'classnames'
import { LineChartContent } from 'sourcegraph'
import { useDebouncedCallback } from 'use-debounce'
import { curveLinear } from '@visx/curve'
import { ParentSize } from '@visx/responsive'
import { RenderTooltipParams } from '@visx/xychart/lib/components/Tooltip'
import { Axis, GlyphSeries, LineSeries, Tooltip, XYChart, EventEmitterProvider } from '@visx/xychart'

import { XYCHART_EVENT_SOURCE } from '@visx/xychart/lib/constants';
import { format } from 'd3-format'
import { timeFormat } from 'd3-time-format'
import { GridColumns, GridRows } from '@visx/grid'
import { Group } from '@visx/group'
import { GlyphDot } from '@visx/glyph'
import isValidNumber from '@visx/xychart/lib/typeguards/isValidNumber'
import { EventHandlerParams } from '@visx/xychart/lib/types'

import { generateAccessors } from './helpers/generate-accessors'
import { GlyphDotComponent } from './components/GlyphDot'
import { TooltipContent } from './components/TooltipContent'
import { onDatumClick } from '../types'
import { DEFAULT_LINE_STROKE } from './colors'
import { useScales } from './helpers/use-scales'
import { GridScale } from '@visx/grid/lib/types'
import { usePointerEventEmitters } from './helpers/use-event-emitters';
import { noop } from 'rxjs';

// Chart configuration
const WIDTH_PER_TICK = 70
const HEIGHT_PER_TICK = 40
const MARGIN = { top: 10, left: 30, bottom: 20, right: 20 }
const SCALES_CONFIG = {
    x: {
        type: 'time' as const,
        nice: true,
    },
    y: {
        type: 'linear' as const,
        nice: true,
        zero: false,
        clamp: true,
    },
}

// Formatters
const dateFormatter = timeFormat('%d %b')
const formatDate = (date: Date): string => dateFormatter(date)

export interface LineChartProps<Datum extends object> extends Omit<LineChartContent<Datum, keyof Datum>, 'chart'> {
    width: number
    height: number
    onDatumClick: onDatumClick
}

function LineChartContentComponent<Datum extends object>(props: LineChartProps<Datum>): ReactElement {
    const { width, height, data, series, xAxis, onDatumClick } = props

    // Derived
    const innerWidth = width - MARGIN.left - MARGIN.right
    const innerHeight = height - MARGIN.top - MARGIN.bottom

    const numberOfTicksX = Math.max(1, Math.floor(innerWidth / WIDTH_PER_TICK))
    const numberOfTicksY = Math.max(1, Math.floor(innerHeight / HEIGHT_PER_TICK))

    const sortedData = useMemo(
        () => data.sort((firstDatum, secondDatum) => +firstDatum[xAxis.dataKey] - +secondDatum[xAxis.dataKey]),
        [data, xAxis]
    )
    const accessors = useMemo(() => generateAccessors(xAxis, series), [xAxis, series])

    const { config: scalesConfig, xScale, yScale } = useScales({
        config: SCALES_CONFIG,
        data: sortedData,
        width: innerWidth,
        height: innerHeight,
        accessors,
    })

    // state
    const [activeDatum, setActiveDatum] = useState<
        (EventHandlerParams<Datum> & { line: LineChartProps<Datum>['series'][number] }) | null
    >(null)

    // callbacks
    const renderTooltip = useCallback(
        (renderProps: RenderTooltipParams<Datum>) => (
            <TooltipContent
                {...renderProps}
                accessors={accessors}
                series={series}
                className="line-chart__tooltip-content"
            />
        ),
        [accessors, series]
    )

    // Because xychart fires all consumer's handlers twice, we need to debounce our handler
    // Remove debounce when https://github.com/airbnb/visx/issues/1077 will be resolved
    const handlePointerMove = useDebouncedCallback(
        (event: EventHandlerParams<Datum>) => {
            const line = series.find(line => line.dataKey === event.key)

            if (!line) {
                return
            }

            setActiveDatum({
                ...event,
                line,
            })
        },
        0,
        { leading: true }
    )

    const handlePointerOut = useDebouncedCallback(() => setActiveDatum(null))

    // Because xychart fires all consumer's handlers twice, we need to debounce our handler
    // Remove debounce when https://github.com/airbnb/visx/issues/1077 will be resolved
    const handlePointerUpDebounced = useDebouncedCallback((info: EventHandlerParams<Datum>) => {
        const line = series.find(line => line.dataKey === info.key)

        // By types from visx/xychart index can be undefined
        const activeDatumIndex = activeDatum?.index

        if (!info.event || !line || !isValidNumber(activeDatumIndex)) {
            return
        }

        onDatumClick({
            originEvent: info.event as MouseEvent<unknown>,
            link: line?.linkURLs?.[activeDatumIndex],
        })
    })

    // If we pass delayed callback to handle pointer event we will lose event object
    // due reusing event object by react between event handlers. So we have to have sync handler
    // just to preserve event object by event.persist()
    const handlePointerUpSync = useCallback(
        (info: EventHandlerParams<Datum>) => {
            info.event?.persist()

            handlePointerUpDebounced(info)
        },
        [handlePointerUpDebounced]
    )

    const activeDatumLink = activeDatum?.line?.linkURLs?.[activeDatum?.index]
    const rootClasses = classnames('line-chart__content', { 'line-chart__content--with-cursor': !!activeDatumLink })

    const {
        onPointerMove = noop,
        onPointerOut = noop,
        ...otherHandlers
    } = usePointerEventEmitters({ source: XYCHART_EVENT_SOURCE })

    const focused = useRef(false);

    const handleRootPointerMove = useCallback((event: React.PointerEvent) => {
        focused.current = true;
        onPointerMove(event)

    }, [onPointerMove])

    const handleRootPointerOut = useCallback(
        (event: React.PointerEvent) => {
            event.persist();
            focused.current = false

            requestAnimationFrame(() => {
                if (!focused.current) {
                    onPointerOut(event)
                }
            })
        },
        [focused, onPointerOut]
    );

    const eventEmitters = {
        onPointerMove: handleRootPointerMove,
        onPointerOut: handleRootPointerOut,
        ...otherHandlers
    };

    return (
        <div className={rootClasses}>
            <XYChart
                xScale={scalesConfig.x}
                yScale={scalesConfig.y}
                height={height}
                width={width}
                captureEvents={false}
                margin={MARGIN}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerUpSync}
                onPointerOut={handlePointerOut}
            >
                <Group top={MARGIN.top} left={MARGIN.left}>
                    <GridRows
                        scale={yScale as GridScale}
                        numTicks={numberOfTicksY}
                        width={innerWidth}
                        className="line-chart__grid-line"
                    />

                    <GridColumns
                        scale={xScale as GridScale}
                        numTicks={numberOfTicksX}
                        height={innerHeight}
                        className="line-chart__grid-line"
                    />
                </Group>

                <Axis
                    orientation="bottom"
                    tickValues={xScale.ticks(numberOfTicksX)}
                    tickFormat={formatDate}
                    numTicks={numberOfTicksX}
                    axisClassName="line-chart__axis"
                    axisLineClassName="line-chart__axis-line"
                    tickClassName="line-chart__axis-tick"
                />
                <Axis
                    orientation="left"
                    numTicks={numberOfTicksY}
                    tickFormat={format('~s')}
                    axisClassName="line-chart__axis"
                    axisLineClassName="line-chart__axis-line"
                    tickClassName="line-chart__axis-tick"
                />

                {series.map(line => (
                    <Group key={line.dataKey as string}>
                        <LineSeries
                            dataKey={line.dataKey as string}
                            data={sortedData}
                            strokeWidth={3}
                            enableEvents={true}
                            xAccessor={accessors.x}
                            yAccessor={accessors.y[line.dataKey as string]}
                            stroke={line.stroke ?? DEFAULT_LINE_STROKE}
                            curve={curveLinear}
                        />
                    </Group>
                ))}

                <Group
                    pointerEvents='bounding-box'
                    {...eventEmitters}>

                    <rect
                        x={MARGIN.left}
                        y={MARGIN.top}
                        width={innerWidth}
                        height={innerHeight}
                        fill="transparent"
                    />

                    {series.map(line => (
                        <Group key={line.dataKey as string}>

                            <GlyphSeries
                                dataKey={line.dataKey as string}
                                data={sortedData}
                                /* eslint-disable-next-line react/jsx-no-bind */
                                colorAccessor={() => line.stroke ?? DEFAULT_LINE_STROKE}
                                enableEvents={false}
                                xAccessor={accessors.x}
                                yAccessor={accessors.y[line.dataKey as string]}
                                renderGlyph={GlyphDotComponent}
                            />
                        </Group>
                    ))}

                    <Group top={MARGIN.top} left={MARGIN.left}>
                        {activeDatum && (
                            <GlyphDot
                                className="line-chart__glyph line-chart__glyph--active"
                                r={8}
                                fill={activeDatum.line.stroke ?? DEFAULT_LINE_STROKE}
                                cx={xScale(accessors.x(activeDatum.datum))}
                                cy={yScale(accessors.y[activeDatum.key](activeDatum.datum))}
                            />
                        )}
                    </Group>
                </Group>

                <Tooltip
                    className="line-chart__tooltip"
                    showHorizontalCrosshair={false}
                    showVerticalCrosshair={true}
                    snapTooltipToDatumX={false}
                    snapTooltipToDatumY={false}
                    showDatumGlyph={false}
                    showSeriesGlyphs={false}
                    renderTooltip={renderTooltip}
                />
            </XYChart>
        </div>
    )
}

export function LineChart<Datum extends object>(props: LineChartProps<Datum>): ReactElement {
    const { width, height, ...otherProps } = props
    const hasLegend = props.series.every(line => !!line.name)

    if (!hasLegend) {
        return (
            <EventEmitterProvider>
                <LineChartContentComponent {...props} />
            </EventEmitterProvider>
        )
    }

    return (
        <EventEmitterProvider>
            {/* eslint-disable-next-line react/forbid-dom-props */}
            <div style={{ width, height }} className="line-chart">
                {/*
                In case if we have a legend to render we have to have responsive container for chart
                just to calculate right sizes for chart content = rootContainerSizes - legendSizes
            */}
                <ParentSize className="line-chart__content-parent-size">
                    {({ width, height }) => <LineChartContentComponent {...otherProps} width={width} height={height} />}
                </ParentSize>

                <ul className="line-chart__legend">
                    {props.series.map(line => (
                        <li key={line.dataKey.toString()} className="line-chart__legend-item">
                            <div
                                /* eslint-disable-next-line react/forbid-dom-props */
                                style={{ backgroundColor: line.stroke ?? DEFAULT_LINE_STROKE }}
                                className="line-chart__legend-mark"
                            />
                            {line.name}
                        </li>
                    ))}
                </ul>
            </div>
        </EventEmitterProvider>
    )
}
