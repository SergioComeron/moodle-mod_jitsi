<?php
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

namespace Google\Service\Compute\Resource;

use Google\Service\Compute\GlobalFrontendSettings as GlobalFrontendSettingsModel;
use Google\Service\Compute\GlobalFrontendSettingsPatchResponse;

/**
 * The "globalFrontendSettings" collection of methods.
 * Typical usage is:
 *  <code>
 *   $computeService = new Google\Service\Compute(...);
 *   $globalFrontendSettings = $computeService->globalFrontendSettings;
 *  </code>
 */
class GlobalFrontendSettings extends \Google\Service\Resource
{
  protected $apiVersion = '2026-09-01';

  /**
   * Gets the Global Frontend Billing Bundle Settings for a project.
   * (globalFrontendSettings.get)
   *
   * @param string $project Required. Project ID for this request.
   * @param array $optParams Optional parameters.
   * @return GlobalFrontendSettingsModel
   * @throws \Google\Service\Exception
   */
  public function get($project, $optParams = [])
  {
    $params = ['project' => $project];
    $params = array_merge($params, $optParams);
    return $this->call('get', [$params], GlobalFrontendSettingsModel::class);
  }
  /**
   * Updates the Global Frontend Billing Bundle Settings for a project.
   * (globalFrontendSettings.patch)
   *
   * @param string $project Required. Project ID for this request.
   * @param GlobalFrontendSettingsModel $postBody
   * @param array $optParams Optional parameters.
   *
   * @opt_param string requestId An optional request ID to identify requests.
   * @opt_param string updateMask Field mask to support patch. E.g., "type".
   * @return GlobalFrontendSettingsPatchResponse
   * @throws \Google\Service\Exception
   */
  public function patch($project, GlobalFrontendSettingsModel $postBody, $optParams = [])
  {
    $params = ['project' => $project, 'postBody' => $postBody];
    $params = array_merge($params, $optParams);
    return $this->call('patch', [$params], GlobalFrontendSettingsPatchResponse::class);
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(GlobalFrontendSettings::class, 'Google_Service_Compute_Resource_GlobalFrontendSettings');
