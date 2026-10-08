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

class GlobalFrontendSettings extends \Google\Model
{
  /**
   * Bundling is not active.
   */
  public const BUNDLE_TYPE_BUNDLE_TYPE_UNSPECIFIED = 'BUNDLE_TYPE_UNSPECIFIED';
  /**
   * Standard Global Frontend bundle.
   */
  public const BUNDLE_TYPE_GLOBAL_FRONT_END = 'GLOBAL_FRONT_END';
  /**
   * Ala Carte mode.
   */
  public const BUNDLE_TYPE_INDIVIDUAL = 'INDIVIDUAL';
  /**
   * Customer-settable bundle type.
   *
   * @var string
   */
  public $bundleType;
  /**
   * Output only. [Output Only] Creation timestamp in RFC3339 text format.
   *
   * @var string
   */
  public $creationTimestamp;
  /**
   * Output only. [Output Only] An optional description of this resource.
   *
   * @var string
   */
  public $description;
  /**
   * Output only. For optimistic locking.
   *
   * @var string
   */
  public $etag;
  /**
   * Output only. [Output Only] The unique identifier for the resource. This
   * identifier is defined by the server.
   *
   * @var string
   */
  public $id;
  /**
   * Output only. OUTPUT_ONLY fields [Output Only] Name of the resource. Must be
   * 1-63 characters long and match the regular expression
   * `[a-z]([-a-z0-9]*[a-z0-9])?` which means the first character must be a
   * lowercase letter, and all following characters must be a dash, lowercase
   * letter, or digit, except the last character, which cannot be a dash.
   *
   * @var string
   */
  public $name;
  /**
   * Output only. [Output Only] Server-defined URL for the resource.
   *
   * @var string
   */
  public $selfLink;

  /**
   * Customer-settable bundle type.
   *
   * Accepted values: BUNDLE_TYPE_UNSPECIFIED, GLOBAL_FRONT_END, INDIVIDUAL
   *
   * @param self::BUNDLE_TYPE_* $bundleType
   */
  public function setBundleType($bundleType)
  {
    $this->bundleType = $bundleType;
  }
  /**
   * @return self::BUNDLE_TYPE_*
   */
  public function getBundleType()
  {
    return $this->bundleType;
  }
  /**
   * Output only. [Output Only] Creation timestamp in RFC3339 text format.
   *
   * @param string $creationTimestamp
   */
  public function setCreationTimestamp($creationTimestamp)
  {
    $this->creationTimestamp = $creationTimestamp;
  }
  /**
   * @return string
   */
  public function getCreationTimestamp()
  {
    return $this->creationTimestamp;
  }
  /**
   * Output only. [Output Only] An optional description of this resource.
   *
   * @param string $description
   */
  public function setDescription($description)
  {
    $this->description = $description;
  }
  /**
   * @return string
   */
  public function getDescription()
  {
    return $this->description;
  }
  /**
   * Output only. For optimistic locking.
   *
   * @param string $etag
   */
  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  /**
   * @return string
   */
  public function getEtag()
  {
    return $this->etag;
  }
  /**
   * Output only. [Output Only] The unique identifier for the resource. This
   * identifier is defined by the server.
   *
   * @param string $id
   */
  public function setId($id)
  {
    $this->id = $id;
  }
  /**
   * @return string
   */
  public function getId()
  {
    return $this->id;
  }
  /**
   * Output only. OUTPUT_ONLY fields [Output Only] Name of the resource. Must be
   * 1-63 characters long and match the regular expression
   * `[a-z]([-a-z0-9]*[a-z0-9])?` which means the first character must be a
   * lowercase letter, and all following characters must be a dash, lowercase
   * letter, or digit, except the last character, which cannot be a dash.
   *
   * @param string $name
   */
  public function setName($name)
  {
    $this->name = $name;
  }
  /**
   * @return string
   */
  public function getName()
  {
    return $this->name;
  }
  /**
   * Output only. [Output Only] Server-defined URL for the resource.
   *
   * @param string $selfLink
   */
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  /**
   * @return string
   */
  public function getSelfLink()
  {
    return $this->selfLink;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(GlobalFrontendSettings::class, 'Google_Service_Compute_GlobalFrontendSettings');
