/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

jest.mock('./assign_bundles_to_workers.ts');
jest.mock('./opensearch_dashboards_platform_plugins.ts');
jest.mock('./get_plugin_bundles.ts');
jest.mock('../common/theme_tags.ts');
jest.mock('./filter_by_id.ts');
jest.mock('../limits.ts');

jest.mock('os', () => {
  const realOs = jest.requireActual('os');
  jest.spyOn(realOs, 'cpus').mockImplementation(() => {
    return ['foo'] as any;
  });
  return realOs;
});

import Path from 'path';
import { REPO_ROOT } from '@osd/utils';
import { createAbsolutePathSerializer } from '@osd/dev-utils';

import { OptimizerConfig, ParsedOptions } from './optimizer_config';
import { parseThemeTags } from '../common';

expect.addSnapshotSerializer(createAbsolutePathSerializer());

beforeEach(() => {
  delete process.env.OSD_OPTIMIZER_MAX_WORKERS;
  delete process.env.OSD_OPTIMIZER_NO_CACHE;
  delete process.env.OSD_OPTIMIZER_THEMES;
  jest.clearAllMocks();
});

describe('OptimizerConfig::parseOptions()', () => {
  it('validates that repoRoot is absolute', () => {
    expect(() =>
      OptimizerConfig.parseOptions({ repoRoot: 'foo/bar' })
    ).toThrowErrorMatchingInlineSnapshot(`"repoRoot must be an absolute path"`);
  });

  it('validates that pluginScanDirs are absolute', () => {
    expect(() =>
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: ['foo/bar'],
      })
    ).toThrowErrorMatchingInlineSnapshot(`"pluginScanDirs must all be absolute paths"`);
  });

  it('validates that pluginPaths are absolute', () => {
    expect(() =>
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginPaths: ['foo/bar'],
      })
    ).toThrowErrorMatchingInlineSnapshot(`"pluginPaths must all be absolute paths"`);
  });

  it('validates that extraPluginScanDirs are absolute', () => {
    expect(() =>
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        extraPluginScanDirs: ['foo/bar'],
      })
    ).toThrowErrorMatchingInlineSnapshot(`"extraPluginScanDirs must all be absolute paths"`);
  });

  it('validates that maxWorkerCount is a number', () => {
    expect(() => {
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        maxWorkerCount: NaN,
      });
    }).toThrowErrorMatchingInlineSnapshot(`"worker count must be a number"`);
  });

  it('defaults to * theme when dist = true', () => {
    OptimizerConfig.parseOptions({
      repoRoot: REPO_ROOT,
      dist: true,
    });

    expect(parseThemeTags).toBeCalledWith('*');
  });

  it('defaults to OSD_OPTIMIZER_THEMES when dist = false', () => {
    process.env.OSD_OPTIMIZER_THEMES = 'foo';

    OptimizerConfig.parseOptions({
      repoRoot: REPO_ROOT,
      dist: false,
    });

    expect(parseThemeTags).toBeCalledWith('foo');
  });

  it('applies defaults', () => {
    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": true,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 2,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [
          <absolute path>/src/plugins,
          <absolute path>/plugins,
          <absolute path>/opensearch-dashboards-extra,
        ],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        cache: false,
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": false,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 2,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [
          <absolute path>/src/plugins,
          <absolute path>/plugins,
          <absolute path>/opensearch-dashboards-extra,
        ],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        examples: true,
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": true,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 2,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [
          <absolute path>/src/plugins,
          <absolute path>/plugins,
          <absolute path>/examples,
          <absolute path>/opensearch-dashboards-extra,
        ],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": true,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 2,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [
          <absolute path>/src/plugins,
          <absolute path>/plugins,
          <absolute path>/opensearch-dashboards-extra,
        ],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: [Path.resolve(REPO_ROOT, 'x/y/z'), '/outside/of/repo'],
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": true,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 2,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [
          <absolute path>/x/y/z,
          "/outside/of/repo",
        ],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    process.env.OSD_OPTIMIZER_MAX_WORKERS = '100';
    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: [],
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": true,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 100,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    process.env.OSD_OPTIMIZER_NO_CACHE = '0';
    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: [],
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": false,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 100,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    process.env.OSD_OPTIMIZER_NO_CACHE = '1';
    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: [],
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": false,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 100,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    process.env.OSD_OPTIMIZER_NO_CACHE = '1';
    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: [],
        cache: true,
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": false,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 100,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);

    delete process.env.OSD_OPTIMIZER_NO_CACHE;
    expect(
      OptimizerConfig.parseOptions({
        repoRoot: REPO_ROOT,
        pluginScanDirs: [],
        cache: true,
      })
    ).toMatchInlineSnapshot(`
      Object {
        "cache": true,
        "dist": false,
        "filters": Array [],
        "includeCoreBundle": false,
        "inspectWorkers": false,
        "maxWorkerCount": 100,
        "outputRoot": <absolute path>,
        "pluginPaths": Array [],
        "pluginScanDirs": Array [],
        "profileWebpack": false,
        "repoRoot": <absolute path>,
        "themeTags": undefined,
        "watch": false,
      }
    `);
  });
});

/**
 * NOTE: this method is basically just calling others, so we're mocking out the return values
 * of each function with a Symbol, including the return values of OptimizerConfig.parseOptions
 * and just making sure that the arguments are coming from where we expect
 */
describe('OptimizerConfig::create()', () => {
  const assignBundlesToWorkers: jest.Mock = jest.requireMock('./assign_bundles_to_workers.ts')
    .assignBundlesToWorkers;
  const findOpenSearchDashboardsPlatformPlugins: jest.Mock = jest.requireMock(
    './opensearch_dashboards_platform_plugins.ts'
  ).findOpenSearchDashboardsPlatformPlugins;
  const getPluginBundles: jest.Mock = jest.requireMock('./get_plugin_bundles.ts').getPluginBundles;
  const filterById: jest.Mock = jest.requireMock('./filter_by_id.ts').filterById;
  const readLimits: jest.Mock = jest.requireMock('../limits.ts').readLimits;

  beforeEach(() => {
    if ('mock' in OptimizerConfig.parseOptions) {
      (OptimizerConfig.parseOptions as jest.Mock).mockRestore();
    }

    assignBundlesToWorkers.mockReturnValue([
      { config: Symbol('worker config 1') },
      { config: Symbol('worker config 2') },
    ]);
    findOpenSearchDashboardsPlatformPlugins.mockReturnValue(Symbol('new platform plugins'));
    getPluginBundles.mockReturnValue([Symbol('bundle1'), Symbol('bundle2')]);
    filterById.mockReturnValue(Symbol('filtered bundles'));
    readLimits.mockReturnValue(Symbol('limits'));

    jest.spyOn(OptimizerConfig, 'parseOptions').mockImplementation((): {
      [key in keyof ParsedOptions]: any;
    } => ({
      cache: Symbol('parsed cache'),
      dist: Symbol('parsed dist'),
      maxWorkerCount: Symbol('parsed max worker count'),
      pluginPaths: Symbol('parsed plugin paths'),
      pluginScanDirs: Symbol('parsed plugin scan dirs'),
      repoRoot: Symbol('parsed repo root'),
      outputRoot: Symbol('parsed output root'),
      watch: Symbol('parsed watch'),
      themeTags: Symbol('theme tags'),
      inspectWorkers: Symbol('parsed inspect workers'),
      profileWebpack: Symbol('parsed profile webpack'),
      filters: [],
      includeCoreBundle: false,
    }));
  });

  it('passes parsed options to findOpenSearchDashboardsPlatformPlugins, getBundles, and assignBundlesToWorkers', () => {
    const config = OptimizerConfig.create({
      repoRoot: REPO_ROOT,
    });

    expect(config).toMatchInlineSnapshot(`
      OptimizerConfig {
        "bundles": Symbol(filtered bundles),
        "cache": Symbol(parsed cache),
        "dist": Symbol(parsed dist),
        "inspectWorkers": Symbol(parsed inspect workers),
        "limits": Symbol(limits),
        "maxWorkerCount": Symbol(parsed max worker count),
        "plugins": Symbol(new platform plugins),
        "profileWebpack": Symbol(parsed profile webpack),
        "repoRoot": Symbol(parsed repo root),
        "themeTags": Symbol(theme tags),
        "watch": Symbol(parsed watch),
      }
    `);

    expect(findOpenSearchDashboardsPlatformPlugins.mock).toMatchInlineSnapshot(`
      Object {
        "calls": Array [
          Array [
            Symbol(parsed plugin scan dirs),
            Symbol(parsed plugin paths),
          ],
        ],
        "instances": Array [
          [Window],
        ],
        "invocationCallOrder": Array [
          21,
        ],
        "lastCall": Array [
          Symbol(parsed plugin scan dirs),
          Symbol(parsed plugin paths),
        ],
        "results": Array [
          Object {
            "type": "return",
            "value": Symbol(new platform plugins),
          },
        ],
      }
    `);

    expect(filterById.mock).toMatchInlineSnapshot(`
      Object {
        "calls": Array [
          Array [
            Array [],
            Array [
              Symbol(bundle1),
              Symbol(bundle2),
            ],
          ],
        ],
        "instances": Array [
          [Window],
        ],
        "invocationCallOrder": Array [
          23,
        ],
        "lastCall": Array [
          Array [],
          Array [
            Symbol(bundle1),
            Symbol(bundle2),
          ],
        ],
        "results": Array [
          Object {
            "type": "return",
            "value": Symbol(filtered bundles),
          },
        ],
      }
    `);

    expect(getPluginBundles.mock).toMatchInlineSnapshot(`
      Object {
        "calls": Array [
          Array [
            Symbol(new platform plugins),
            Symbol(parsed repo root),
            Symbol(parsed output root),
          ],
        ],
        "instances": Array [
          [Window],
        ],
        "invocationCallOrder": Array [
          22,
        ],
        "lastCall": Array [
          Symbol(new platform plugins),
          Symbol(parsed repo root),
          Symbol(parsed output root),
        ],
        "results": Array [
          Object {
            "type": "return",
            "value": Array [
              Symbol(bundle1),
              Symbol(bundle2),
            ],
          },
        ],
      }
    `);
  });
});
