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

class GetHealthOperationMetadataHealthInfo extends \Google\Model
{
  /**
   * The slot availability is in SLO.
   */
  public const AVAILABILITY_SLO_STATUS_AVAILABILITY_SLO_STATUS_IN_SLO = 'AVAILABILITY_SLO_STATUS_IN_SLO';
  /**
   * The slot availability is out of SLO.
   */
  public const AVAILABILITY_SLO_STATUS_AVAILABILITY_SLO_STATUS_OUT_OF_SLO = 'AVAILABILITY_SLO_STATUS_OUT_OF_SLO';
  /**
   * The slot availability is unknown.
   */
  public const AVAILABILITY_SLO_STATUS_AVAILABILITY_SLO_STATUS_SLO_UNKNOWN = 'AVAILABILITY_SLO_STATUS_SLO_UNKNOWN';
  /**
   * Unspecified availability SLO status.
   */
  public const AVAILABILITY_SLO_STATUS_AVAILABILITY_SLO_STATUS_UNSPECIFIED = 'AVAILABILITY_SLO_STATUS_UNSPECIFIED';
  /**
   * The reservation slot is healthy.
   */
  public const HEALTH_STATUS_HEALTH_STATUS_HEALTHY = 'HEALTH_STATUS_HEALTHY';
  /**
   * The reservation slot is unhealthy.
   */
  public const HEALTH_STATUS_HEALTH_STATUS_UNHEALTHY = 'HEALTH_STATUS_UNHEALTHY';
  /**
   * Unspecified health status.
   */
  public const HEALTH_STATUS_HEALTH_STATUS_UNSPECIFIED = 'HEALTH_STATUS_UNSPECIFIED';
  /**
   * The repair is because of critical failures, that are scoped outside
   * emergent maintenance
   */
  public const REPAIR_CATEGORY_REPAIR_CATEGORY_CRITICAL_FAILURE = 'REPAIR_CATEGORY_CRITICAL_FAILURE';
  /**
   * The repair is because of an emergent maintenance
   */
  public const REPAIR_CATEGORY_REPAIR_CATEGORY_EMERGENT_MAINTENANCE = 'REPAIR_CATEGORY_EMERGENT_MAINTENANCE';
  /**
   * The repair is because of a planned maintenance
   */
  public const REPAIR_CATEGORY_REPAIR_CATEGORY_PLANNED_MAINTENANCE = 'REPAIR_CATEGORY_PLANNED_MAINTENANCE';
  /**
   * Unspecified repair category.
   */
  public const REPAIR_CATEGORY_REPAIR_CATEGORY_UNSPECIFIED = 'REPAIR_CATEGORY_UNSPECIFIED';
  /**
   * The repair is because of a user reported fault
   */
  public const REPAIR_CATEGORY_REPAIR_CATEGORY_USER_REPORTED_FAULT = 'REPAIR_CATEGORY_USER_REPORTED_FAULT';
  /**
   * The slot is unhealthy because there is a pending repair, waiting for
   * customer approval
   */
  public const UNHEALTHY_REASON_UNHEALTHY_REASON_PENDING_USER_APPROVAL = 'UNHEALTHY_REASON_PENDING_USER_APPROVAL';
  /**
   * The slot is unhealthy because repair is in progress
   */
  public const UNHEALTHY_REASON_UNHEALTHY_REASON_REPAIRING = 'UNHEALTHY_REASON_REPAIRING';
  /**
   * The slot is unhealthy because a vm cannot be scheduled on it, and no
   * repairs are running on the slot
   */
  public const UNHEALTHY_REASON_UNHEALTHY_REASON_UNSCHEDULABLE = 'UNHEALTHY_REASON_UNSCHEDULABLE';
  /**
   * Unspecified unhealthy reason.
   */
  public const UNHEALTHY_REASON_UNHEALTHY_REASON_UNSPECIFIED = 'UNHEALTHY_REASON_UNSPECIFIED';
  /**
   * Output only. The availability SLO status.
   *
   * @var string
   */
  public $availabilitySloStatus;
  /**
   * Output only. The health status.
   *
   * @var string
   */
  public $healthStatus;
  /**
   * Output only. The repair category.
   *
   * @var string
   */
  public $repairCategory;
  /**
   * Output only. The reason for unhealthy status.
   *
   * @var string
   */
  public $unhealthyReason;
  /**
   * Output only. The time when health info was updated.
   *
   * @var string
   */
  public $updateTime;

  /**
   * Output only. The availability SLO status.
   *
   * Accepted values: AVAILABILITY_SLO_STATUS_IN_SLO,
   * AVAILABILITY_SLO_STATUS_OUT_OF_SLO, AVAILABILITY_SLO_STATUS_SLO_UNKNOWN,
   * AVAILABILITY_SLO_STATUS_UNSPECIFIED
   *
   * @param self::AVAILABILITY_SLO_STATUS_* $availabilitySloStatus
   */
  public function setAvailabilitySloStatus($availabilitySloStatus)
  {
    $this->availabilitySloStatus = $availabilitySloStatus;
  }
  /**
   * @return self::AVAILABILITY_SLO_STATUS_*
   */
  public function getAvailabilitySloStatus()
  {
    return $this->availabilitySloStatus;
  }
  /**
   * Output only. The health status.
   *
   * Accepted values: HEALTH_STATUS_HEALTHY, HEALTH_STATUS_UNHEALTHY,
   * HEALTH_STATUS_UNSPECIFIED
   *
   * @param self::HEALTH_STATUS_* $healthStatus
   */
  public function setHealthStatus($healthStatus)
  {
    $this->healthStatus = $healthStatus;
  }
  /**
   * @return self::HEALTH_STATUS_*
   */
  public function getHealthStatus()
  {
    return $this->healthStatus;
  }
  /**
   * Output only. The repair category.
   *
   * Accepted values: REPAIR_CATEGORY_CRITICAL_FAILURE,
   * REPAIR_CATEGORY_EMERGENT_MAINTENANCE, REPAIR_CATEGORY_PLANNED_MAINTENANCE,
   * REPAIR_CATEGORY_UNSPECIFIED, REPAIR_CATEGORY_USER_REPORTED_FAULT
   *
   * @param self::REPAIR_CATEGORY_* $repairCategory
   */
  public function setRepairCategory($repairCategory)
  {
    $this->repairCategory = $repairCategory;
  }
  /**
   * @return self::REPAIR_CATEGORY_*
   */
  public function getRepairCategory()
  {
    return $this->repairCategory;
  }
  /**
   * Output only. The reason for unhealthy status.
   *
   * Accepted values: UNHEALTHY_REASON_PENDING_USER_APPROVAL,
   * UNHEALTHY_REASON_REPAIRING, UNHEALTHY_REASON_UNSCHEDULABLE,
   * UNHEALTHY_REASON_UNSPECIFIED
   *
   * @param self::UNHEALTHY_REASON_* $unhealthyReason
   */
  public function setUnhealthyReason($unhealthyReason)
  {
    $this->unhealthyReason = $unhealthyReason;
  }
  /**
   * @return self::UNHEALTHY_REASON_*
   */
  public function getUnhealthyReason()
  {
    return $this->unhealthyReason;
  }
  /**
   * Output only. The time when health info was updated.
   *
   * @param string $updateTime
   */
  public function setUpdateTime($updateTime)
  {
    $this->updateTime = $updateTime;
  }
  /**
   * @return string
   */
  public function getUpdateTime()
  {
    return $this->updateTime;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(GetHealthOperationMetadataHealthInfo::class, 'Google_Service_Compute_GetHealthOperationMetadataHealthInfo');
