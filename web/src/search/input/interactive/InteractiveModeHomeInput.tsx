import * as React from 'react'
import * as H from 'history'
import { QueryState, submitSearch } from '../../helpers'
import * as GQL from '../../../../../shared/src/graphql/schema'
import { Form } from '../../../components/Form'
import { SelectedFiltersRow } from './SelectedFiltersRow'
import { SearchButton } from '../SearchButton'
import { Subscription, Subject } from 'rxjs'
import { ThemeProps } from '../../../../../shared/src/theme'
import { SettingsCascadeProps } from '../../../../../shared/src/settings/settings'
import { ThemePreferenceProps } from '../../theme'
import { ActivationProps } from '../../../../../shared/src/components/activation/Activation'
import { FiltersToTypeAndValue } from '../../../../../shared/src/search/interactive/util'
import { SuggestionTypes, SuggestionTypeKeys } from '../../../../../shared/src/search/suggestions/util'
import { AddFilterRow } from './AddFilterRow'
import { QueryInput } from '../QueryInput'

interface InteractiveModeProps extends SettingsCascadeProps, ThemeProps, ThemePreferenceProps, ActivationProps {
    location: H.Location
    history: H.History
    navbarSearchState: QueryState
    onNavbarQueryChange: (userQuery: QueryState) => void
    patternType: GQL.SearchPatternType
    togglePatternType: () => void
    toggleSearchMode: (e: React.MouseEvent<HTMLAnchorElement>) => void
}

interface InteractiveInputState {
    /**
     * This is the source of truth for the selected filters. The key is a unique key to match
     * the particular selected filter with its value. The type is the raw type of filter, as listed
     * in SuggestionTypes. The value is the current value of that particular filter.
     * */
    filtersInQuery: FiltersToTypeAndValue
}

// INTERACTIVE_SEARCH_TODO: This component is being built for the navbar use case.
// Need to add a mode for search page.
export default class InteractiveModeHomeInput extends React.Component<InteractiveModeProps, InteractiveInputState> {
    private numFiltersAddedToQuery = 0
    private subscriptions = new Subscription()
    private componentUpdates = new Subject<InteractiveModeProps>()

    constructor(props: InteractiveModeProps) {
        super(props)

        this.state = {
            filtersInQuery: {},
        }
        this.subscriptions.add(
            this.componentUpdates.subscribe(props => {
                const searchParams = new URLSearchParams(props.location.search)
                const filtersInQuery: FiltersToTypeAndValue = {}
                for (const t of SuggestionTypeKeys) {
                    const itemsOfType = searchParams.getAll(t)
                    itemsOfType.map((item, i) => {
                        filtersInQuery[`${t} ${i}`] = { type: t, value: item, editable: false }
                    })
                }
                this.numFiltersAddedToQuery = Object.keys(filtersInQuery).length
                this.setState({ filtersInQuery })
            })
        )
    }

    public componentDidMount(): void {
        this.componentUpdates.next(this.props)
    }

    public componentWillUnmount(): void {
        this.subscriptions.unsubscribe()
    }

    /**
     * Adds a new filter to the filtersInQuery state field.
     * We use the filter name and the number of values added as the key.
     * Keys must begin with the filter name, as defined in `SuggestionTypes`.
     * We use this to identify filter values when building
     * the search URL in {@link interactiveBuildSearchURLQuery}.
     */
    private addNewFilter = (filterType: SuggestionTypes): void => {
        const filterKey = `${filterType} ${this.numFiltersAddedToQuery}`
        this.numFiltersAddedToQuery++
        this.setState(state => ({
            filtersInQuery: { ...state.filtersInQuery, [filterKey]: { type: filterType, value: '', editable: true } },
        }))
    }

    private onFilterEdited = (filterKey: string, value: string): void => {
        this.setState(state => ({
            filtersInQuery: {
                ...state.filtersInQuery,
                [filterKey]: {
                    ...state.filtersInQuery[filterKey],
                    value,
                },
            },
        }))
    }

    private onFilterDeleted = (filterKey: string): void => {
        this.setState(state => {
            const newState = state.filtersInQuery
            delete newState[filterKey]
            return { filtersInQuery: newState }
        })
    }

    private toggleFilterEditable = (filterKey: string): void => {
        this.setState(state => ({
            filtersInQuery: {
                ...state.filtersInQuery,
                [filterKey]: {
                    ...state.filtersInQuery[filterKey],
                    editable: !state.filtersInQuery[filterKey].editable,
                },
            },
        }))
    }

    private onSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
        e.preventDefault()

        submitSearch(
            this.props.history,
            this.props.navbarSearchState.query,
            'nav',
            this.props.patternType,
            undefined,
            this.state.filtersInQuery
        )
    }

    public render(): JSX.Element | null {
        return (
            <div className="interactive-mode-input">
                <div className="interactive-mode-input__top-nav">
                    <div className="global-navbar__search-box-container d-none d-sm-flex">
                        <Form onSubmit={this.onSubmit}>
                            <div className="d-flex align-items-start">
                                <QueryInput
                                    location={this.props.location}
                                    history={this.props.history}
                                    value={this.props.navbarSearchState}
                                    hasGlobalQueryBehavior={true}
                                    autoFocus={true}
                                    onChange={this.props.onNavbarQueryChange}
                                    patternType={this.props.patternType}
                                    togglePatternType={this.props.togglePatternType}
                                    filterQuery={this.state.filtersInQuery}
                                    withoutSuggestions={true}
                                />
                                <SearchButton />
                            </div>
                        </Form>
                    </div>
                </div>
                <div>
                    <SelectedFiltersRow
                        filtersInQuery={this.state.filtersInQuery}
                        navbarQuery={this.props.navbarSearchState}
                        onFilterEdited={this.onFilterEdited}
                        onFilterDeleted={this.onFilterDeleted}
                        toggleFilterEditable={this.toggleFilterEditable}
                        isHomepage={true}
                    />
                    <AddFilterRow onAddNewFilter={this.addNewFilter} homepage={true} />
                </div>
            </div>
        )
    }
}
