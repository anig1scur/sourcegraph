import React from 'react'
import { Toggle } from '@sourcegraph/branded/src/components/Toggle'
import { useRedesignToggle, REDESIGN_CLASS_NAME } from '@sourcegraph/wildcard'

export const RedesignToggle: React.FC = () => {
    const { isRedesignEnabled, setIsRedesignEnabled } = useRedesignToggle()

    const handleRedesignToggle = (): void => {
        setIsRedesignEnabled(!isRedesignEnabled)
        document.documentElement.classList.toggle(REDESIGN_CLASS_NAME, !isRedesignEnabled)
    }

    return (
        <div className="px-2 py-1">
            <div className="d-flex align-items-center">
                <div className="mr-2">Redesign enabled</div>
                <Toggle
                    title="Redesign theme enabled"
                    value={isRedesignEnabled}
                    // eslint-disable-next-line react/jsx-no-bind
                    onToggle={handleRedesignToggle}
                />
            </div>
        </div>
    )
}
