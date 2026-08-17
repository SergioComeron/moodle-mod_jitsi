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

class AvailabilityConfigRegionsConfig extends \Google\Collection
{
  protected $collection_key = 'regionIntervals';
  protected $regionIntervalsType = AvailabilityConfigRegionsConfigRegionInterval::class;
  protected $regionIntervalsDataType = 'array';

  /**
   * Required. List of regions and time windows where video is available. If a
   * region is specified multiple times, the union of all intervals is used.
   *
   * @param AvailabilityConfigRegionsConfigRegionInterval[] $regionIntervals
   */
  public function setRegionIntervals($regionIntervals)
  {
    $this->regionIntervals = $regionIntervals;
  }
  /**
   * @return AvailabilityConfigRegionsConfigRegionInterval[]
   */
  public function getRegionIntervals()
  {
    return $this->regionIntervals;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(AvailabilityConfigRegionsConfig::class, 'Google_Service_YouTube_AvailabilityConfigRegionsConfig');
