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

import { mapExists } from './map_exists';
import { mapQueryString } from './map_query_string';
import {
  IIndexPattern,
  IFieldType,
  buildExistsFilter,
  buildEmptyFilter,
} from '../../../../../common';

describe('filter manager utilities', () => {
  describe('mapExists()', () => {
    let indexPattern: IIndexPattern;

    beforeEach(() => {
      indexPattern = {
        id: 'index',
      } as IIndexPattern;
    });

    test('should return the key and value for matching filters', async () => {
      const filter = buildExistsFilter({ name: '_type' } as IFieldType, indexPattern);
      const result = mapExists(filter);

      expect(result).toHaveProperty('key', '_type');
      expect(result).toHaveProperty('value', 'exists');
    });

    test('should return undefined for none matching', (done) => {
      const filter = buildEmptyFilter(true);

      try {
        mapQueryString(filter);
      } catch (e) {
        expect(e).toBe(filter);
        done();
      }
    });
  });
});
