import React from 'react'
import { Redirect } from 'react-router'
import { namespaceAreaRoutes } from '../../namespaces/routes'
import { lazyComponent } from '../../util/lazyComponent'
import { UserAreaRoute } from './UserArea'

const UserSettingsArea = lazyComponent(() => import('../settings/UserSettingsArea'), 'UserSettingsArea')

const redirectToUserProfile: UserAreaRoute['render'] = props => <Redirect to={`${props.url}/settings/profile`} />

export const userAreaRoutes: readonly UserAreaRoute[] = [
    {
        path: '/settings',
        render: props => (
            <UserSettingsArea
                {...props}
                routes={props.userSettingsAreaRoutes}
                sideBarItems={props.userSettingsSideBarItems}
            />
        ),
    },
    ...namespaceAreaRoutes,

    // Redirect from /users/:username -> /users/:username/settings/profile.
    {
        path: '/',
        exact: true,
        render: redirectToUserProfile,
    },
    // Redirect from previous /users/:username/account -> /users/:username/settings/profile.
    {
        path: '/account',
        render: redirectToUserProfile,
    },
]
