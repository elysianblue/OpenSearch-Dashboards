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
import { mapPhrase } from './map_phrase';
import { PhraseFilter, Filter } from '../../../../../common';

describe('filter manager utilities', () => {
  describe('mapPhrase()', () => {
    test('should return the key and value for matching filters', async () => {
      const filter = {
        meta: { index: 'logstash-*' },
        query: { match: { _type: { query: 'apache', type: 'phrase' } } },
      } as PhraseFilter;

      const result = mapPhrase(filter);

      expect(result).toHaveProperty('value');
      expect(result).toHaveProperty('key', '_type');

      if (result.value) {
        const displayName = result.value();
        expect(displayName).toBe('apache');
      }
    });

    test('should return undefined for none matching', (done) => {
      const filter = {
        meta: { index: 'logstash-*' },
        query: { query_string: { query: 'foo:bar' } },
      } as Filter;

      try {
        mapPhrase(filter);
      } catch (e) {
        expect(e).toBe(filter);
        done();
      }
    });
  });
});
