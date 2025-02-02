import { isEqual } from 'lodash'
import { from, Observable, of, throwError } from 'rxjs'
import { catchError, distinctUntilChanged, map, shareReplay, switchMap } from 'rxjs/operators'
import { gql } from '../graphql/graphql'
import * as GQL from '../graphql/schema'
import { PlatformContext } from '../platform/context'
import { asError, createAggregateError } from '../util/errors'
import { ConfiguredRegistryExtension, extensionIDsFromSettings, toConfiguredRegistryExtension } from './extension'

/**
 * @returns An observable that emits the list of extensions configured in the viewer's final settings upon
 * subscription and each time it changes.
 */
export function viewerConfiguredExtensions({
    settings,
    requestGraphQL,
}: Pick<PlatformContext, 'settings' | 'requestGraphQL'>): Observable<ConfiguredRegistryExtension[]> {
    return from(settings).pipe(
        map(settings => extensionIDsFromSettings(settings)),
        distinctUntilChanged((a, b) => isEqual(a, b)),
        switchMap(extensionIDs => queryConfiguredRegistryExtensions({ requestGraphQL }, extensionIDs)),
        catchError(error => throwError(asError(error))),
        // TODO: Restore reference counter after refactoring contributions service
        // to not unsubscribe from existing entries when new entries are registered,
        // in order to ensure that the source is unsubscribed from.
        shareReplay(1)
    )
}

/**
 * Query the GraphQL API for registry metadata about the extensions given in {@link extensionIDs}.
 *
 * @returns An observable that emits once with the results.
 */
export function queryConfiguredRegistryExtensions(
    // TODO(tj): can copy this over to extension host, just replace platformContext.requestGraphQL
    // with mainThreadAPI.requestGraphQL
    { requestGraphQL }: Pick<PlatformContext, 'requestGraphQL'>,
    extensionIDs: string[]
): Observable<ConfiguredRegistryExtension[]> {
    if (extensionIDs.length === 0) {
        return of([])
    }
    const variables: GQL.IExtensionsOnExtensionRegistryArguments = {
        first: extensionIDs.length,
        prioritizeExtensionIDs: extensionIDs,
    }
    return from(
        requestGraphQL<GQL.IQuery>({
            request: gql`
                query Extensions($first: Int!, $prioritizeExtensionIDs: [String!]!) {
                    extensionRegistry {
                        extensions(first: $first, prioritizeExtensionIDs: $prioritizeExtensionIDs) {
                            nodes {
                                id
                                extensionID
                                url
                                manifest {
                                    raw
                                }
                                viewerCanAdminister
                            }
                        }
                    }
                }
            `,
            variables,
            mightContainPrivateInfo: false,
        })
    ).pipe(
        map(({ data, errors }) => {
            if (!data?.extensionRegistry?.extensions?.nodes) {
                throw createAggregateError(errors)
            }
            return data.extensionRegistry.extensions.nodes.map(
                ({ id, extensionID, url, manifest, viewerCanAdminister }) => ({
                    id,
                    extensionID,
                    url,
                    manifest: manifest ? { raw: manifest.raw } : null,
                    viewerCanAdminister,
                })
            )
        }),
        map(registryExtensions => {
            const configuredExtensions: ConfiguredRegistryExtension[] = []
            for (const extensionID of extensionIDs) {
                const registryExtension = registryExtensions.find(extension => extension.extensionID === extensionID)
                configuredExtensions.push(
                    registryExtension
                        ? toConfiguredRegistryExtension(registryExtension)
                        : { id: extensionID, manifest: null, rawManifest: null, registryExtension: undefined }
                )
            }
            return configuredExtensions
        })
    )
}
