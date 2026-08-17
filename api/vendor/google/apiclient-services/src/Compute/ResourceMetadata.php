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

namespace Google\Service\Compute;

class ResourceMetadata extends \Google\Model
{
  /**
   * The version of the API interface that this resource was retrieved through.
   * For example, `"2025-01-01"` or `"2025-01-01-preview"`.
   *
   * @var string
   */
  public $apiVersion;
  /**
   * The canonical resource type name in the format of a resource type as
   * defined by [AIP-123](https://google.aip.dev/123). For example,
   * `"compute.googleapis.com/Instance"`.
   *
   * @var string
   */
  public $resourceType;

  /**
   * The version of the API interface that this resource was retrieved through.
   * For example, `"2025-01-01"` or `"2025-01-01-preview"`.
   *
   * @param string $apiVersion
   */
  public function setApiVersion($apiVersion)
  {
    $this->apiVersion = $apiVersion;
  }
  /**
   * @return string
   */
  public function getApiVersion()
  {
    return $this->apiVersion;
  }
  /**
   * The canonical resource type name in the format of a resource type as
   * defined by [AIP-123](https://google.aip.dev/123). For example,
   * `"compute.googleapis.com/Instance"`.
   *
   * @param string $resourceType
   */
  public function setResourceType($resourceType)
  {
    $this->resourceType = $resourceType;
  }
  /**
   * @return string
   */
  public function getResourceType()
  {
    return $this->resourceType;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ResourceMetadata::class, 'Google_Service_Compute_ResourceMetadata');
