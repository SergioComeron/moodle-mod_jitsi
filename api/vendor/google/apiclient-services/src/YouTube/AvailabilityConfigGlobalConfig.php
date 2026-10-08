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

namespace Google\Service\YouTube;

class AvailabilityConfigGlobalConfig extends \Google\Collection
{
  protected $collection_key = 'excludedRegionCodes';
  /**
   * Optional. Regions where video is blocked
   *
   * @var string[]
   */
  public $excludedRegionCodes;
  protected $intervalType = Interval::class;
  protected $intervalDataType = '';

  /**
   * Optional. Regions where video is blocked
   *
   * @param string[] $excludedRegionCodes
   */
  public function setExcludedRegionCodes($excludedRegionCodes)
  {
    $this->excludedRegionCodes = $excludedRegionCodes;
  }
  /**
   * @return string[]
   */
  public function getExcludedRegionCodes()
  {
    return $this->excludedRegionCodes;
  }
  /**
   * Default time window where video is available for all non-blocked regions
   * Not supported for upcoming / active live broadcasts. If start time is
   * unspecified, video is already available If end time is unspecified, video
   * is available forever Specified start and end times cannot be more than five
   * years in the future.
   *
   * @param Interval $interval
   */
  public function setInterval(Interval $interval)
  {
    $this->interval = $interval;
  }
  /**
   * @return Interval
   */
  public function getInterval()
  {
    return $this->interval;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(AvailabilityConfigGlobalConfig::class, 'Google_Service_YouTube_AvailabilityConfigGlobalConfig');
