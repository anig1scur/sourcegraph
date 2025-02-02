import expect from 'expect'
import { commonWebGraphQlResults } from './graphQlResults'
import {
    RepoGroupsResult,
    SearchResult,
    SearchSuggestionsResult,
    WebGraphQlOperations,
    AutoDefinedSearchContextsResult,
} from '../graphql-operations'
import { Driver, createDriverForTest, percySnapshot } from '@sourcegraph/shared/src/testing/driver'
import { afterEachSaveScreenshotIfFailed } from '@sourcegraph/shared/src/testing/screenshotReporter'
import { WebIntegrationTestContext, createWebIntegrationTestContext } from './context'
import { test } from 'mocha'
import { siteGQLID, siteID } from './jscontext'
import { SharedGraphQlOperations, SymbolKind } from '@sourcegraph/shared/src/graphql-operations'
import { SearchEvent } from '../search/stream'
import { Key } from 'ts-key-enum'

const searchResults = (): SearchResult => ({
    search: {
        results: {
            __typename: 'SearchResults',
            limitHit: true,
            matchCount: 30,
            approximateResultCount: '30+',
            missing: [],
            cloning: [],
            repositoriesCount: 372,
            timedout: [],
            indexUnavailable: false,
            dynamicFilters: [
                {
                    value: 'archived:yes',
                    label: 'archived:yes',
                    count: 5,
                    limitHit: true,
                    kind: 'repo',
                },
                {
                    value: 'fork:yes',
                    label: 'fork:yes',
                    count: 46,
                    limitHit: true,
                    kind: 'repo',
                },
                {
                    value: 'repo:^github\\.com/Algorilla/manta-ray$',
                    label: 'github.com/Algorilla/manta-ray',
                    count: 1,
                    limitHit: false,
                    kind: 'repo',
                },
            ],
            results: [
                {
                    __typename: 'Repository',
                    id: 'UmVwb3NpdG9yeTozODcxOTM4Nw==',
                    name: 'github.com/Algorilla/manta-ray',
                    label: {
                        html:
                            '\u003Cp\u003E\u003Ca href="/github.com/Algorilla/manta-ray" rel="nofollow"\u003Egithub.com/Algorilla/manta-ray\u003C/a\u003E\u003C/p\u003E\n',
                    },
                    url: '/github.com/Algorilla/manta-ray',
                    detail: { html: '\u003Cp\u003ERepository match\u003C/p\u003E\n' },
                    matches: [],
                },
            ],
            alert: null,
            elapsedMilliseconds: 103,
        },
    },
})

const commonSearchGraphQLResults: Partial<WebGraphQlOperations & SharedGraphQlOperations> = {
    ...commonWebGraphQlResults,
    Search: searchResults,
    SearchSuggestions: (): SearchSuggestionsResult => ({
        search: {
            suggestions: [],
        },
    }),
    RepoGroups: (): RepoGroupsResult => ({
        repoGroups: [],
    }),
    AutoDefinedSearchContexts: (): AutoDefinedSearchContextsResult => ({
        autoDefinedSearchContexts: [],
    }),
}

describe('Search', () => {
    let driver: Driver
    before(async () => {
        driver = await createDriverForTest()
    })
    after(() => driver?.close())
    let testContext: WebIntegrationTestContext
    beforeEach(async function () {
        testContext = await createWebIntegrationTestContext({
            driver,
            currentTest: this.currentTest!,
            directory: __dirname,
        })
    })
    afterEachSaveScreenshotIfFailed(() => driver.page)
    afterEach(() => testContext?.dispose())

    const waitAndFocusInput = async () => {
        await driver.page.waitForSelector('.monaco-editor .view-lines')
        await driver.page.click('.monaco-editor .view-lines')
    }

    const getSearchFieldValue = (driver: Driver): Promise<string | undefined> =>
        driver.page.evaluate(() => document.querySelector<HTMLTextAreaElement>('#monaco-query-input textarea')?.value)

    describe('Search filters', () => {
        test('Search filters are shown on search result pages and clicking them triggers a new search', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            const dynamicFilters = ['archived:yes', 'repo:^github\\.com/Algorilla/manta-ray$']
            const origQuery = 'foo'
            for (const filter of dynamicFilters) {
                await driver.page.goto(
                    `${driver.sourcegraphBaseUrl}/search?q=${encodeURIComponent(origQuery)}&patternType=literal`
                )
                await driver.page.waitForSelector(`[data-testid="filter-chip"][value=${JSON.stringify(filter)}]`)
                await driver.page.click(`[data-testid="filter-chip"][value=${JSON.stringify(filter)}]`)
                await driver.page.waitForFunction(
                    expectedQuery => {
                        const url = new URL(document.location.href)
                        const query = url.searchParams.get('q')
                        return query && query.trim() === expectedQuery
                    },
                    { timeout: 5000 },
                    `${origQuery} ${filter}`
                )
            }
        })
    })

    describe('Filter completion', () => {
        test('Completing a negated filter should insert the filter with - prefix', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
                SearchSuggestions: () => ({
                    search: {
                        suggestions: [],
                    },
                }),
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search')
            await driver.page.waitForSelector('#monaco-query-input')
            await driver.replaceText({
                selector: '#monaco-query-input',
                newText: '-repo',
                enterTextMethod: 'type',
            })
            await driver.page.waitForSelector('.monaco-query-input-container .suggest-widget.visible')
            await driver.findElementWithText('-repo', {
                action: 'click',
                wait: { timeout: 5000 },
                selector: '.monaco-query-input-container .suggest-widget.visible span',
            })
            expect(await getSearchFieldValue(driver)).toStrictEqual('-repo:')
        })
    })

    describe('Suggestions', () => {
        test('Typing in the search field shows relevant suggestions', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
                SearchSuggestions: () => ({
                    search: {
                        suggestions: [
                            { __typename: 'Repository', name: 'github.com/auth0/go-jwt-middleware' },
                            {
                                __typename: 'Symbol',
                                name: 'OnError',
                                containerName: 'jwtmiddleware',
                                url: '/github.com/auth0/go-jwt-middleware/-/blob/jwtmiddleware.go#L56:1-56:14',
                                kind: SymbolKind.STRUCT,
                                location: {
                                    resource: {
                                        path: 'jwtmiddleware.go',
                                        repository: { name: 'github.com/auth0/go-jwt-middleware' },
                                    },
                                },
                            },
                            {
                                __typename: 'File',
                                path: 'jwtmiddleware.go',
                                name: 'jwtmiddleware.go',
                                isDirectory: false,
                                url: '/github.com/auth0/go-jwt-middleware/-/blob/jwtmiddleware.go',
                                repository: { name: 'github.com/auth0/go-jwt-middleware' },
                            },
                        ],
                    },
                }),
            })
            // Repo autocomplete from homepage
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search')
            // Using id selector rather than `test-` classes as Monaco doesn't allow customizing classes
            await driver.page.waitForSelector('#monaco-query-input')
            await driver.replaceText({
                selector: '#monaco-query-input',
                newText: 'go-jwt-middlew',
                enterTextMethod: 'type',
            })
            await driver.page.waitForSelector('.monaco-query-input-container .suggest-widget.visible')
            await driver.findElementWithText('github.com/auth0/go-jwt-middleware', {
                action: 'click',
                wait: { timeout: 5000 },
                selector: '.monaco-query-input-container .suggest-widget.visible span',
            })
            expect(await getSearchFieldValue(driver)).toStrictEqual('repo:^github\\.com/auth0/go-jwt-middleware$ ')

            // Submit search
            await driver.page.keyboard.press(Key.Enter)

            // File autocomplete from repo search bar
            await driver.page.waitForSelector('#monaco-query-input')
            await driver.page.focus('#monaco-query-input')
            await driver.page.keyboard.type('jwtmi')
            await driver.page.waitForSelector('.monaco-query-input-container .suggest-widget.visible')
            await driver.findElementWithText('jwtmiddleware.go', {
                selector: '.monaco-query-input-container .suggest-widget.visible span',
                wait: { timeout: 5000 },
            })
            await driver.page.keyboard.press(Key.Tab)
            expect(await getSearchFieldValue(driver)).toStrictEqual(
                'repo:^github\\.com/auth0/go-jwt-middleware$ file:^jwtmiddleware\\.go$ '
            )

            // Symbol autocomplete in top search bar
            await driver.page.keyboard.type('On')
            await driver.page.waitForSelector('.monaco-query-input-container .suggest-widget.visible')
            await driver.findElementWithText('OnError', {
                selector: '.monaco-query-input-container .suggest-widget.visible span',
                wait: { timeout: 5000 },
            })
        })
    })

    describe('Search field value', () => {
        test('Is set from the URL query parameter when loading a search-related page', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=foo')
            await driver.page.waitForSelector('#monaco-query-input')
            expect(await getSearchFieldValue(driver)).toStrictEqual('foo')
            // Field value is cleared when navigating to a non search-related page
            await driver.page.waitForSelector('[data-testid="batch-changes"]')
            await driver.page.click('[data-testid="batch-changes"]')
            expect(await getSearchFieldValue(driver)).toStrictEqual('')
            // Field value is restored when the back button is pressed
            await driver.page.goBack()
            expect(await getSearchFieldValue(driver)).toStrictEqual('foo')
        })
    })

    describe('Case sensitivity toggle', () => {
        test('Clicking toggle turns on case sensitivity', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search')
            await driver.page.waitForSelector('.test-query-input', { visible: true })
            await driver.page.waitForSelector('.test-case-sensitivity-toggle')
            await waitAndFocusInput()
            await driver.page.type('.test-query-input', 'test')
            await driver.page.click('.test-case-sensitivity-toggle')
            await driver.assertWindowLocation('/search?q=test&patternType=literal&case=yes')
        })

        test('Clicking toggle turns off case sensitivity and removes case= URL parameter', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=literal&case=yes')
            await driver.page.waitForSelector('.test-query-input', { visible: true })
            await driver.page.waitForSelector('.test-case-sensitivity-toggle')
            await driver.page.click('.test-case-sensitivity-toggle')
            await driver.assertWindowLocation('/search?q=test&patternType=literal')
        })
    })

    describe('Structural search toggle', () => {
        test('Clicking toggle turns on structural search', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search')
            await driver.page.waitForSelector('.test-query-input', { visible: true })
            await driver.page.waitForSelector('.test-structural-search-toggle')
            await waitAndFocusInput()
            await driver.page.type('.test-query-input', 'test')
            await driver.page.click('.test-structural-search-toggle')
            await driver.assertWindowLocation('/search?q=test&patternType=structural')
        })

        test('Clicking toggle turns on structural search and removes existing patternType parameter', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=regexp')
            await waitAndFocusInput()
            await driver.page.waitForSelector('.test-query-input', { visible: true })
            await driver.page.waitForSelector('.test-structural-search-toggle')
            await driver.page.click('.test-structural-search-toggle')
            await driver.assertWindowLocation('/search?q=test&patternType=structural')
        })

        test('Clicking toggle turns off structural saerch and reverts to default pattern type', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=structural')
            await driver.page.waitForSelector('.test-query-input', { visible: true })
            await driver.page.waitForSelector('.test-structural-search-toggle')
            await driver.page.click('.test-structural-search-toggle')
            await driver.assertWindowLocation('/search?q=test&patternType=literal')
        })
    })

    describe('Search button', () => {
        test('Clicking search button executes search', async () => {
            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
            })

            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=regexp')
            await driver.page.waitForSelector('.test-search-button', { visible: true })
            // Note: Delay added because this test has been intermittently failing without it. Monaco search bar may drop events if it gets too many too fast.
            await driver.page.keyboard.type(' hello', { delay: 50 })
            await driver.page.click('.test-search-button')
            await driver.assertWindowLocation('/search?q=test+hello&patternType=regexp')
        })
    })

    describe('Streaming search', () => {
        const viewerSettingsWithStreamingSearch: Partial<WebGraphQlOperations> = {
            ViewerSettings: () => ({
                viewerSettings: {
                    subjects: [
                        {
                            __typename: 'DefaultSettings',
                            settingsURL: null,
                            viewerCanAdminister: false,
                            latestSettings: {
                                id: 0,
                                contents: JSON.stringify({ experimentalFeatures: { searchStreaming: true } }),
                            },
                        },
                        {
                            __typename: 'Site',
                            id: siteGQLID,
                            siteID,
                            latestSettings: {
                                id: 470,
                                contents: JSON.stringify({ experimentalFeatures: { searchStreaming: true } }),
                            },
                            settingsURL: '/site-admin/global-settings',
                            viewerCanAdminister: true,
                        },
                    ],
                    final: JSON.stringify({}),
                },
            }),
        }

        test('Streaming search', async () => {
            const searchStreamEvents: SearchEvent[] = [
                {
                    type: 'matches',
                    data: [
                        { type: 'repo', repository: 'github.com/sourcegraph/sourcegraph' },
                        {
                            type: 'file',
                            lineMatches: [],
                            name: 'stream.ts',
                            repository: 'github.com/sourcegraph/sourcegraph',
                        },
                        {
                            type: 'file',
                            lineMatches: [],
                            name: 'stream.ts',
                            repository: 'github.com/sourcegraph/sourcegraph',
                            version: 'abcd',
                        },
                        {
                            type: 'file',
                            lineMatches: [],
                            name: 'stream.ts',
                            repository: 'github.com/sourcegraph/sourcegraph',
                            branches: ['test/branch'],
                        },
                    ],
                },
                { type: 'done', data: {} },
            ]

            testContext.overrideGraphQL({ ...commonSearchGraphQLResults, ...viewerSettingsWithStreamingSearch })
            testContext.overrideSearchStreamEvents(searchStreamEvents)

            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=regexp')
            await driver.page.waitForSelector('.test-search-result', { visible: true })

            const results = await driver.page.evaluate(() =>
                [...document.querySelectorAll('.test-search-result-label')].map(label =>
                    (label.textContent || '').trim()
                )
            )
            expect(results).toEqual([
                'github.com/sourcegraph/sourcegraph',
                'sourcegraph/sourcegraph › stream.ts',
                'sourcegraph/sourcegraph@abcd › stream.ts',
                'sourcegraph/sourcegraph@test/branch › stream.ts',
            ])
        })

        test('Streaming search with error', async () => {
            const searchStreamEvents: SearchEvent[] = [
                {
                    type: 'error',
                    data: { message: 'Search is invalid' },
                },
            ]

            testContext.overrideGraphQL({ ...commonSearchGraphQLResults, ...viewerSettingsWithStreamingSearch })
            testContext.overrideSearchStreamEvents(searchStreamEvents)

            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=regexp')
            await driver.page.waitForSelector('[data-testid="search-results-list-error"]', { visible: true })

            const results = await driver.page.evaluate(
                () => document.querySelector('[data-testid="search-results-list-error"]')?.textContent
            )
            expect(results).toContain('Search is invalid')
        })

        test('Streaming diff search syntax highlighting', async () => {
            const searchStreamEvents: SearchEvent[] = [
                {
                    type: 'matches',
                    data: [
                        {
                            type: 'commit',
                            label:
                                '[sourcegraph/sourcegraph](/gitlab.sgdev.org/sourcegraph/sourcegraph) › [Rijnard van Tonder](/gitlab.sgdev.org/sourcegraph/sourcegraph/-/commit/b6dd338737c090fdab31d324542bfdaa7ce9f766): [search: if not specified, set fork:no by default (#8739)](/gitlab.sgdev.org/sourcegraph/sourcegraph/-/commit/b6dd338737c090fdab31d324542bfdaa7ce9f766)',
                            url:
                                '/gitlab.sgdev.org/sourcegraph/sourcegraph/-/commit/b6dd338737c090fdab31d324542bfdaa7ce9f766',
                            detail:
                                '[`b6dd338` one year ago](/gitlab.sgdev.org/sourcegraph/sourcegraph/-/commit/b6dd338737c090fdab31d324542bfdaa7ce9f766)',
                            content:
                                "```diff\nweb/src/regression/search.test.ts web/src/regression/search.test.ts\n@@ -434,0 +435,3 @@ describe('Search regression test suite', () => {\n+        test('Fork repos excluded by default', async () => {\n+            const urlQuery = buildSearchURLQuery('type:repo sgtest/mux', GQL.SearchPatternType.regexp, false)\n+            await driver.page.goto(config.sourcegraphBaseUrl + '/search?' + urlQuery)\n@@ -434,0 +439,4 @@ describe('Search regression test suite', () => {\n+        })\n+        test('Forked repos included by by fork option', async () => {\n+            const urlQuery = buildSearchURLQuery('type:repo sgtest/mux fork:yes', GQL.SearchPatternType.regexp, false)\n+            await driver.page.goto(config.sourcegraphBaseUrl + '/search?' + urlQuery)\n```",
                            ranges: [
                                [-1, 30, 4],
                                [-4, 30, 4],
                                [3, 9, 4],
                                [4, 63, 4],
                                [8, 9, 4],
                                [9, 63, 4],
                            ],
                        },
                    ],
                },
                { type: 'done', data: {} },
            ]

            const highlightResult: Partial<WebGraphQlOperations> = {
                highlightCode: ({ isLightTheme }) => ({
                    highlightCode: isLightTheme
                        ? '<table><tbody><tr><td class="line" data-line="1"></td><td class="code"><div><span style="color:#657b83;">web/src/regression/search.test.ts web/src/regression/search.test.ts\n</span></div></td></tr><tr><td class="line" data-line="2"></td><td class="code"><div><span style="color:#268bd2;">@@ -434,0 +435,3 @@ </span><span style="color:#cb4b16;">describe(&#39;Search regression test suite&#39;, () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="3"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+        test(&#39;Fork repos excluded by default&#39;, async () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="4"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+            const urlQuery = buildSearchURLQuery(&#39;type:repo sgtest/mux&#39;, GQL.SearchPatternType.regexp, false)\n</span></div></td></tr><tr><td class="line" data-line="5"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+            await driver.page.goto(config.sourcegraphBaseUrl + &#39;/search?&#39; + urlQuery)\n</span></div></td></tr><tr><td class="line" data-line="6"></td><td class="code"><div><span style="color:#268bd2;">@@ -434,0 +439,4 @@ </span><span style="color:#cb4b16;">describe(&#39;Search regression test suite&#39;, () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="7"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+        })\n</span></div></td></tr><tr><td class="line" data-line="8"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+        test(&#39;Forked repos included by by fork option&#39;, async () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="9"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+            const urlQuery = buildSearchURLQuery(&#39;type:repo sgtest/mux fork:yes&#39;, GQL.SearchPatternType.regexp, false)\n</span></div></td></tr><tr><td class="line" data-line="10"></td><td class="code"><div><span style="background-color:#deeade;color:#2b3750;">+            await driver.page.goto(config.sourcegraphBaseUrl + &#39;/search?&#39; + urlQuery)</span></div></td></tr></tbody></table>'
                        : '<table><tbody><tr><td class="line" data-line="1"></td><td class="code"><div><span style="color:#969896;">web/src/regression/search.test.ts web/src/regression/search.test.ts\n</span></div></td></tr><tr><td class="line" data-line="2"></td><td class="code"><div><span style="color:#268bd2;">@@ -434,0 +435,3 @@ </span><span style="color:#8fa1b3;">describe(&#39;Search regression test suite&#39;, () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="3"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+        test(&#39;Fork repos excluded by default&#39;, async () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="4"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+            const urlQuery = buildSearchURLQuery(&#39;type:repo sgtest/mux&#39;, GQL.SearchPatternType.regexp, false)\n</span></div></td></tr><tr><td class="line" data-line="5"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+            await driver.page.goto(config.sourcegraphBaseUrl + &#39;/search?&#39; + urlQuery)\n</span></div></td></tr><tr><td class="line" data-line="6"></td><td class="code"><div><span style="color:#268bd2;">@@ -434,0 +439,4 @@ </span><span style="color:#8fa1b3;">describe(&#39;Search regression test suite&#39;, () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="7"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+        })\n</span></div></td></tr><tr><td class="line" data-line="8"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+        test(&#39;Forked repos included by by fork option&#39;, async () =&gt; {\n</span></div></td></tr><tr><td class="line" data-line="9"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+            const urlQuery = buildSearchURLQuery(&#39;type:repo sgtest/mux fork:yes&#39;, GQL.SearchPatternType.regexp, false)\n</span></div></td></tr><tr><td class="line" data-line="10"></td><td class="code"><div><span style="background-color:#0e2414;color:#f2f4f8;">+            await driver.page.goto(config.sourcegraphBaseUrl + &#39;/search?&#39; + urlQuery)</span></div></td></tr></tbody></table>',
                }),
            }

            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
                ...viewerSettingsWithStreamingSearch,
                ...highlightResult,
            })
            testContext.overrideSearchStreamEvents(searchStreamEvents)

            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test%20type:diff&patternType=regexp')
            await driver.page.waitForSelector('.search-result-match__code-excerpt .selection-highlight', {
                visible: true,
            })
            await driver.page.waitForSelector('#monaco-query-input', { visible: true })

            await percySnapshot(driver.page, 'Streaming diff search syntax highlighting')
        })

        test('Streaming commit search syntax highlighting', async () => {
            const searchStreamEvents: SearchEvent[] = [
                {
                    type: 'matches',
                    data: [
                        {
                            type: 'commit',
                            label:
                                '[sourcegraph/sourcegraph](/github.com/sourcegraph/sourcegraph) › [Camden Cheek](/github.com/sourcegraph/sourcegraph/-/commit/f7d28599cad80e200913d9c4612618a73199bac1): [search: Incorporate search blitz (#19567)](/github.com/sourcegraph/sourcegraph/-/commit/f7d28599cad80e200913d9c4612618a73199bac1)',
                            url:
                                '/github.com/sourcegraph/sourcegraph/-/commit/f7d28599cad80e200913d9c4612618a73199bac1',
                            detail:
                                '[`f7d2859` 2 days ago](/github.com/sourcegraph/sourcegraph/-/commit/f7d28599cad80e200913d9c4612618a73199bac1)',
                            content:
                                '```COMMIT_EDITMSG\nsearch: Incorporate search blitz (#19567)\n\nIncorporates search blitz into sourcegraph/sourcegraph so it has access to the internal streaming client\n```',
                            ranges: [
                                [3, 37, 5],
                                [3, 49, 5],
                            ],
                        },
                    ],
                },
                { type: 'done', data: {} },
            ]

            const highlightResult: Partial<WebGraphQlOperations> = {
                highlightCode: ({ isLightTheme }) => ({
                    highlightCode: isLightTheme
                        ? '<table><tbody><tr><td class="line" data-line="1"></td><td class="code"><div><span style="color:#657b83;">search: Incorporate search blitz (#19567)\n</span></div></td></tr><tr><td class="line" data-line="2"></td><td class="code"><div><span style="color:#657b83;">\n</span></div></td></tr><tr><td class="line" data-line="3"></td><td class="code"><div><span style="color:#657b83;">Incorporates search blitz into sourcegraph/sourcegraph so it has access to the internal streaming client</span></div></td></tr></tbody></table>'
                        : '<table><tbody><tr><td class="line" data-line="1"></td><td class="code"><div><span style="color:#c0c5ce;">search: Incorporate search blitz (#19567)\n</span></div></td></tr><tr><td class="line" data-line="2"></td><td class="code"><div><span style="color:#c0c5ce;">\n</span></div></td></tr><tr><td class="line" data-line="3"></td><td class="code"><div><span style="color:#c0c5ce;">Incorporates search blitz into sourcegraph/sourcegraph so it has access to the internal streaming client</span></div></td></tr></tbody></table>',
                }),
            }

            testContext.overrideGraphQL({
                ...commonSearchGraphQLResults,
                ...viewerSettingsWithStreamingSearch,
                ...highlightResult,
            })
            testContext.overrideSearchStreamEvents(searchStreamEvents)

            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=graph%20type:commit&patternType=regexp')
            await driver.page.waitForSelector('.search-result-match__code-excerpt .selection-highlight', {
                visible: true,
            })
            await driver.page.waitForSelector('#monaco-query-input', { visible: true })

            await percySnapshot(driver.page, 'Streaming commit search syntax highlighting')
        })
    })

    describe('Search contexts', () => {
        const viewerSettingsWithSearchContexts: Partial<WebGraphQlOperations> = {
            ViewerSettings: () => ({
                viewerSettings: {
                    subjects: [
                        {
                            __typename: 'DefaultSettings',
                            settingsURL: null,
                            viewerCanAdminister: false,
                            latestSettings: {
                                id: 0,
                                contents: JSON.stringify({ experimentalFeatures: { showSearchContext: true } }),
                            },
                        },
                        {
                            __typename: 'Site',
                            id: siteGQLID,
                            siteID,
                            latestSettings: {
                                id: 470,
                                contents: JSON.stringify({ experimentalFeatures: { showSearchContext: true } }),
                            },
                            settingsURL: '/site-admin/global-settings',
                            viewerCanAdminister: true,
                        },
                    ],
                    final: JSON.stringify({}),
                },
            }),
        }
        const testContextForSearchContexts: Partial<WebGraphQlOperations> = {
            ...commonSearchGraphQLResults,
            ...viewerSettingsWithSearchContexts,
            AutoDefinedSearchContexts: () => ({
                autoDefinedSearchContexts: [
                    {
                        __typename: 'SearchContext',
                        id: '1',
                        spec: 'global',
                        description: '',
                        autoDefined: true,
                        repositories: [],
                    },
                    {
                        __typename: 'SearchContext',
                        id: '2',
                        spec: '@test',
                        description: '',
                        autoDefined: true,
                        repositories: [],
                    },
                ],
            }),
            UserRepositories: () => ({
                node: {
                    repositories: {
                        totalCount: 1,
                        nodes: [
                            {
                                id: '1',
                                name: 'repo',
                                viewerCanAdminister: false,
                                createdAt: '',
                                url: '',
                                isPrivate: false,
                                mirrorInfo: { cloned: true, cloneInProgress: false, updatedAt: null },
                                externalRepository: { serviceType: '', serviceID: '' },
                            },
                        ],
                        pageInfo: { hasNextPage: false },
                    },
                },
            }),
        }

        beforeEach(() => {
            testContext.overrideGraphQL(testContextForSearchContexts)
        })

        afterEach(async () => {
            await driver.page.evaluate(() => localStorage.clear())
        })

        const getSelectedSearchContextSpec = () =>
            driver.page.evaluate(() => document.querySelector('.test-selected-search-context-spec')?.textContent)

        const isSearchContextDropdownVisible = () =>
            driver.page.evaluate(
                () => document.querySelector<HTMLButtonElement>('.test-search-context-dropdown') !== null
            )

        const isSearchContextDropdownDisabled = () =>
            driver.page.evaluate(
                () => document.querySelector<HTMLButtonElement>('.test-search-context-dropdown')?.disabled
            )
        test('Search context selected based on URL', async () => {
            testContext.overrideGraphQL({
                ...testContextForSearchContexts,
                IsSearchContextAvailable: () => ({
                    isSearchContextAvailable: true,
                }),
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=context:global+test&patternType=regexp', {
                waitUntil: 'networkidle2',
            })
            await driver.page.waitForSelector('.test-selected-search-context-spec', { visible: true })
            expect(await getSelectedSearchContextSpec()).toStrictEqual('context:global')
        })

        test('Missing context param should default to global context', async () => {
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=regexp')
            await driver.page.waitForSelector('.test-selected-search-context-spec', { visible: true })
            expect(await getSelectedSearchContextSpec()).toStrictEqual('context:global')
        })

        test('Unavailable search context should remain in the query and disable the search context dropdown', async () => {
            await driver.page.goto(
                driver.sourcegraphBaseUrl + '/search?q=context:%40unavailableCtx+test&patternType=regexp',
                { waitUntil: 'networkidle2' }
            )
            await driver.page.waitForSelector('.test-selected-search-context-spec', { visible: true })
            await driver.page.waitForSelector('#monaco-query-input')
            expect(await getSearchFieldValue(driver)).toStrictEqual('context:@unavailableCtx test')
            expect(await isSearchContextDropdownDisabled()).toBeTruthy()
        })

        test('Search context dropdown should not be visible if user has no repositories', async () => {
            testContext.overrideGraphQL({
                ...testContextForSearchContexts,
                UserRepositories: () => ({
                    node: {
                        repositories: {
                            totalCount: 0,
                            nodes: [],
                            pageInfo: { hasNextPage: false },
                        },
                    },
                }),
            })
            await driver.page.goto(driver.sourcegraphBaseUrl + '/search?q=test&patternType=regexp')
            await driver.page.waitForSelector('#monaco-query-input')
            expect(await isSearchContextDropdownVisible()).toBeFalsy()
        })
    })
})
