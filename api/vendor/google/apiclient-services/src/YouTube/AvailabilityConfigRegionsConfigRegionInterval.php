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

class AvailabilityConfigRegionsConfigRegionInterval extends \Google\Model
{
  protected $intervalType = Interval::class;
  protected $intervalDataType = '';
  /**
   * Required. Region where video is available
   *
   * @var string
   */
  public $regionCode;

  /**
   * Time window where video is available for the region. Not supported for
   * upcoming / active live broadcasts. If start time is unspecified, video is
   * already available If end time is unspecified, video is available forever
   * Specified start and end times cannot be more than five years in the future.
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
  /**
   * Required. Region where video is available
   *
   * @param string $regionCode
   */
  public function setRegionCode($regionCode)
  {
    $this->regionCode = $regionCode;
  }
  /**
   * @return string
   */
  public function getRegionCode()
  {
    return $this->regionCode;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(AvailabilityConfigRegionsConfigRegionInterval::class, 'Google_Service_YouTube_AvailabilityConfigRegionsConfigRegionInterval');
