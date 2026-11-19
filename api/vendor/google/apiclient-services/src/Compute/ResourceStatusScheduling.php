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

class ResourceStatusScheduling extends \Google\Model
{
  /**
   * CAPACITY_OPTIMIZED capacity leverages redundancies (e.g. power, cooling) at
   * the data center during normal operating conditions. In the event of
   * infrastructure failures at data center (e.g. power and/or cooling
   * failures), this workload may be disrupted. As a consequence, it has a
   * weaker availability SLO than STANDARD.
   */
  public const PROTECTION_TIER_PROTECTION_TIER_CAPACITY_OPTIMIZED = 'PROTECTION_TIER_CAPACITY_OPTIMIZED';
  /**
   * STANDARD protection for workload that should be protected by redundancies
   * (e.g. power, cooling) at the data center level. In the event of
   * infrastructure failures at data center (e.g. power and/or cooling
   * failures), this workload is expected to continue as normal using the
   * redundancies.
   */
  public const PROTECTION_TIER_PROTECTION_TIER_STANDARD = 'PROTECTION_TIER_STANDARD';
  /**
   * Unspecified protection tier.
   */
  public const PROTECTION_TIER_PROTECTION_TIER_UNSPECIFIED = 'PROTECTION_TIER_UNSPECIFIED';
  /**
   * Specifies the availability domain to place the instance in. The value must
   * be a number between 1 and the number of availability domains specified in
   * the spread placement policy attached to the instance.
   *
   * @var int
   */
  public $availabilityDomain;
  /**
   * Output only. Specifies the timestamp, when the instance will start graceful
   * shutdown process, in RFC3339 text format.
   *
   * @var string
   */
  public $gracefulShutdownTimestamp;
  /**
   * Output only. Protection tier for the workload which specifies the workload
   * expectations in the event of infrastructure failures at data center (e.g.
   * power and/or cooling failures).
   *
   * @var string
   */
  public $protectionTier;
  /**
   * Time in future when the instance will be terminated inRFC3339 text format.
   *
   * @var string
   */
  public $terminationTimestamp;

  /**
   * Specifies the availability domain to place the instance in. The value must
   * be a number between 1 and the number of availability domains specified in
   * the spread placement policy attached to the instance.
   *
   * @param int $availabilityDomain
   */
  public function setAvailabilityDomain($availabilityDomain)
  {
    $this->availabilityDomain = $availabilityDomain;
  }
  /**
   * @return int
   */
  public function getAvailabilityDomain()
  {
    return $this->availabilityDomain;
  }
  /**
   * Output only. Specifies the timestamp, when the instance will start graceful
   * shutdown process, in RFC3339 text format.
   *
   * @param string $gracefulShutdownTimestamp
   */
  public function setGracefulShutdownTimestamp($gracefulShutdownTimestamp)
  {
    $this->gracefulShutdownTimestamp = $gracefulShutdownTimestamp;
  }
  /**
   * @return string
   */
  public function getGracefulShutdownTimestamp()
  {
    return $this->gracefulShutdownTimestamp;
  }
  /**
   * Output only. Protection tier for the workload which specifies the workload
   * expectations in the event of infrastructure failures at data center (e.g.
   * power and/or cooling failures).
   *
   * Accepted values: PROTECTION_TIER_CAPACITY_OPTIMIZED,
   * PROTECTION_TIER_STANDARD, PROTECTION_TIER_UNSPECIFIED
   *
   * @param self::PROTECTION_TIER_* $protectionTier
   */
  public function setProtectionTier($protectionTier)
  {
    $this->protectionTier = $protectionTier;
  }
  /**
   * @return self::PROTECTION_TIER_*
   */
  public function getProtectionTier()
  {
    return $this->protectionTier;
  }
  /**
   * Time in future when the instance will be terminated inRFC3339 text format.
   *
   * @param string $terminationTimestamp
   */
  public function setTerminationTimestamp($terminationTimestamp)
  {
    $this->terminationTimestamp = $terminationTimestamp;
  }
  /**
   * @return string
   */
  public function getTerminationTimestamp()
  {
    return $this->terminationTimestamp;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ResourceStatusScheduling::class, 'Google_Service_Compute_ResourceStatusScheduling');
