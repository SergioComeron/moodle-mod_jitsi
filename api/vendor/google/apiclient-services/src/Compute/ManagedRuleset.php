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

class ManagedRuleset extends \Google\Collection
{
  protected $collection_key = 'ruleIds';
  /**
   * Output only. [Output Only] The change log for this managed ruleset.
   *
   * @var string
   */
  public $changeLog;
  /**
   * Output only. [Output Only] Creation timestamp in RFC3339 text format.
   *
   * @var string
   */
  public $creationTimestamp;
  /**
   * [Output Only] An optional description of this resource.
   *
   * @var string
   */
  public $description;
  /**
   * Output only. [Output Only] The unique identifier for the resource. This
   * identifier is defined by the server.
   *
   * @var string
   */
  public $id;
  /**
   * Name of the resource. Generated internally when the resource is created.
   * The name must be 1-63 characters long, and comply withRFC1035.
   * Specifically, the name must be 1-63 characters long and match the regular
   * expression `[a-z]([-a-z0-9]*[a-z0-9])?` which means the first character
   * must be a lowercase letter, and all following characters must be a dash,
   * lowercase letter, or digit, except the last character, which cannot be a
   * dash.
   *
   * @var string
   */
  public $name;
  /**
   * Output only. [Output Only] The list of managed rule IDs that are included
   * in this managed ruleset.
   *
   * @var string[]
   */
  public $ruleIds;
  /**
   * Output only. [Output Only] The managed ruleset identifier that can be
   * configured in Security Policy rules.
   *
   * @var string
   */
  public $rulesetId;
  /**
   * Output only. [Output Only] Server-defined URL for the resource.
   *
   * @var string
   */
  public $selfLink;

  /**
   * Output only. [Output Only] The change log for this managed ruleset.
   *
   * @param string $changeLog
   */
  public function setChangeLog($changeLog)
  {
    $this->changeLog = $changeLog;
  }
  /**
   * @return string
   */
  public function getChangeLog()
  {
    return $this->changeLog;
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
   * [Output Only] An optional description of this resource.
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
   * Name of the resource. Generated internally when the resource is created.
   * The name must be 1-63 characters long, and comply withRFC1035.
   * Specifically, the name must be 1-63 characters long and match the regular
   * expression `[a-z]([-a-z0-9]*[a-z0-9])?` which means the first character
   * must be a lowercase letter, and all following characters must be a dash,
   * lowercase letter, or digit, except the last character, which cannot be a
   * dash.
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
   * Output only. [Output Only] The list of managed rule IDs that are included
   * in this managed ruleset.
   *
   * @param string[] $ruleIds
   */
  public function setRuleIds($ruleIds)
  {
    $this->ruleIds = $ruleIds;
  }
  /**
   * @return string[]
   */
  public function getRuleIds()
  {
    return $this->ruleIds;
  }
  /**
   * Output only. [Output Only] The managed ruleset identifier that can be
   * configured in Security Policy rules.
   *
   * @param string $rulesetId
   */
  public function setRulesetId($rulesetId)
  {
    $this->rulesetId = $rulesetId;
  }
  /**
   * @return string
   */
  public function getRulesetId()
  {
    return $this->rulesetId;
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
class_alias(ManagedRuleset::class, 'Google_Service_Compute_ManagedRuleset');
