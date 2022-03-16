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

import { find, template } from 'lodash';
import { stringify } from 'query-string';
import $ from 'jquery';
import rison from 'rison-node';
import '../../doc_viewer';

import openRowHtml from './table_row/open.html';
import detailsHtml from './table_row/details.html';

import { dispatchRenderComplete, url } from '../../../../../../opensearch_dashboards_utils/public';
import { DOC_HIDE_TIME_COLUMN_SETTING } from '../../../../../common';
import cellTemplateHtml from '../components/table_row/cell.html';
import truncateByHeightTemplateHtml from '../components/table_row/truncate_by_height.html';
import { opensearchFilters } from '../../../../../../data/public';
import { getServices } from '../../../../opensearch_dashboards_services';

// TARDIS Modification
import { send } from '../../../../../../console/public'

const TAGS_WITH_WS = />\s+</g;

/**
 * Remove all of the whitespace between html tags
 * so that inline elements don't have extra spaces.
 */
export function noWhiteSpace(html: string): string {
  return html.replace(TAGS_WITH_WS, '><');
}

// guesstimate at the minimum number of chars wide cells in the table should be
const MIN_LINE_LENGTH = 20;

interface LazyScope extends ng.IScope {
  [key: string]: any;
}

export function createTableRowDirective($compile: ng.ICompileService) {
  const cellTemplate = template(noWhiteSpace(cellTemplateHtml));
  const truncateByHeightTemplate = template(noWhiteSpace(truncateByHeightTemplateHtml));

  return {
    restrict: 'A',
    scope: {
      columns: '=',
      filter: '=',
      indexPattern: '=',
      row: '=osdTableRow',
      onAddColumn: '=?',
      onRemoveColumn: '=?',
    },
    link: ($scope: LazyScope, $el: JQuery) => {
      $el.after('<tr data-test-subj="docTableDetailsRow" class="osdDocTableDetails__row">');
      $el.empty();

      // when we compile the details, we use this $scope
      let $detailsScope: LazyScope;

      // when we compile the toggle button in the summary, we use this $scope
      let $toggleScope;

      // toggle display of the rows details, a full list of the fields from each row
      $scope.toggleRow = () => {
        const $detailsTr = $el.next();

        $scope.open = !$scope.open;

        ///
        // add/remove $details children
        ///

        $detailsTr.toggle($scope.open);

        if (!$scope.open) {
          // close the child scope if it exists
          $detailsScope.$destroy();
          // no need to go any further
          return;
        } else {
          $detailsScope = $scope.$new();
        }

        // empty the details and rebuild it
        $detailsTr.html(detailsHtml);
        $detailsScope.row = $scope.row;
        $detailsScope.hit = $scope.row;
        $detailsScope.uriEncodedId = encodeURIComponent($detailsScope.hit._id);

        $compile($detailsTr)($detailsScope);
      };

      $scope.$watchMulti(['indexPattern.timeFieldName', 'row.highlight', '[]columns'], () => {
        createSummaryRow($scope.row);
      });

      $scope.inlineFilter = function inlineFilter($event: any, type: string) {
        const column = $($event.currentTarget).data().column;
        const field = $scope.indexPattern.fields.getByName(column);
        $scope.filter(field, $scope.flattenedRow[column], type);
      };

      $scope.getContextAppHref = () => {
        const globalFilters: any = getServices().filterManager.getGlobalFilters();
        const appFilters: any = getServices().filterManager.getAppFilters();

        const hash = stringify(
          url.encodeQuery({
            _g: rison.encode({
              filters: globalFilters || [],
            }),
            _a: rison.encode({
              columns: $scope.columns,
              filters: (appFilters || []).map(opensearchFilters.disableFilter),
            }),
          }),
          { encode: false, sort: false }
        );

        return `#/context/${encodeURIComponent($scope.indexPattern.id)}/${encodeURIComponent(
          $scope.row._id
        )}?${hash}`;
      };

      // create a tr element that lists the value for each *column*
      function createSummaryRow(row: any) {
        const indexPattern = $scope.indexPattern;
        $scope.flattenedRow = indexPattern.flattenHit(row);
        
        // TARDIS Modification
        indexPattern.dfirstatus = true;

        // We just create a string here because its faster.
        const newHtmls = [openRowHtml];

        const mapping = indexPattern.fields.getByName;
        const hideTimeColumn = getServices().uiSettings.get(DOC_HIDE_TIME_COLUMN_SETTING, false);
        // TARDIS Modification

        if (indexPattern.timeFieldName && !hideTimeColumn) {
          newHtmls.push(
            cellTemplate({
              timefield: true,
              formatted: _displayField(row, indexPattern.timeFieldName),
              filterable: mapping(indexPattern.timeFieldName).filterable && $scope.filter,
              column: indexPattern.timeFieldName,
            })
          );
        }

        // TARDIS Modification
        // Set $scope.dfirstatus based on the value of the 'dfir_status' field in the returned record
        // This is used to set the button color to indicate marked records. - JWR
        if ($scope.flattenedRow['dfir_status'] == 'malicious') {
          $scope.dfirstatus = true;
        } else if ($scope.flattenedRow['dfir_status'] == 'unknown') {
          $scope.dfirstatus = false;
        }
        // TARDIS Modification
        // Set toggleStatus() method to execute update_by_query ES query when button is clicked by user
        // This modifies the 'dfir_status' field in the record to mark the record as attacker activity.
        $scope.toggleStatus = function toggleStatus() {
          const method = "POST";
          const path = $scope.row._index + "/_update_by_query";
          const data =  "{\n" +
                        "  \"script\": {\n" +
                        "    \"inline\": \"if (ctx._source.dfir_status == \\\"malicious\\\"){ctx._source.dfir_status = \\\"unknown\\\"} else {ctx._source.dfir_status = \\\"malicious\\\"}\"," +
                        "    \"lang\": \"painless\"\n" +
                        "  },\n" +
                        "  \"query\": {\n" +
                        "    \"match\": {\n" +
                        "      \"_id\": \"" + $scope.row._id + "\"\n" +
                        "    }\n" +
                        "  }\n" +
                        "}\n";
          return send(method,path,data);
        }
        // TARDIS Modifcation
        // Push the Status button to the row for rendering to the user
        newHtmls.push(cellTemplate({
          dfirstatus: true,
          timefield: false,
          sourcefield: true,
          formatted: '<button class="kuiButton" ng-click="$parent.dfirstatus = !$parent.dfirstatus" ng-class="{  \'kuiButton--danger\': $parent.dfirstatus, \'kuiButton--basic\': !$parent.dfirstatus }"><span class="kuiButton__icon kuiIcon fa-plus"></span></button>',
          filterable: false,
          column: 'dfir_status'
        }));
        

        $scope.columns.forEach(function (column: any) {
          const isFilterable = mapping(column) && mapping(column).filterable && $scope.filter;
          // TARDIS Modification
          // Add dfirstatus from $scope to 'false' to display after timestamp
          newHtmls.push(
            cellTemplate({
              timefield: false,
              dfirstatus:false,
              sourcefield: column === '_source',
              formatted: _displayField(row, column, true),
              filterable: isFilterable,
              column,
            })
          );
        });

        let $cells = $el.children();
        newHtmls.forEach(function (html, i) {
          const $cell = $cells.eq(i);
          if ($cell.data('discover:html') === html) return;

          const reuse = find($cells.slice(i + 1), function (cell: any) {
            return $.data(cell, 'discover:html') === html;
          });

          const $target = reuse ? $(reuse).detach() : $(html);
          $target.data('discover:html', html);
          const $before = $cells.eq(i - 1);
          if ($before.length) {
            $before.after($target);
          } else {
            $el.append($target);
          }

          // rebuild cells since we modified the children
          $cells = $el.children();

          if (!reuse) {
            $toggleScope = $scope.$new();
            $compile($target)($toggleScope);
          }
        });

        if ($scope.open) {
          $detailsScope.row = row;
        }

        // trim off cells that were not used rest of the cells
        $cells.filter(':gt(' + (newHtmls.length - 1) + ')').remove();
        dispatchRenderComplete($el[0]);
      }

      /**
       * Fill an element with the value of a field
       */
      function _displayField(row: any, fieldName: string, truncate = false) {
        const indexPattern = $scope.indexPattern;
        const text = indexPattern.formatField(row, fieldName);

        if (truncate && text.length > MIN_LINE_LENGTH) {
          return truncateByHeightTemplate({
            body: text,
          });
        }

        return text;
      }
    },
  };
}
