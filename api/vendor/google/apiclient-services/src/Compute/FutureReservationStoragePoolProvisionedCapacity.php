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

class FutureReservationStoragePoolProvisionedCapacity extends \Google\Model
{
  /**
   * Size of the storage pool in GiB.
   *
   * @var string
   */
  public $poolProvisionedCapacityGb;
  /**
   * Provisioned IOPS of the storage pool. Only relevant if the storage pool
   * type is hyperdisk-balanced.
   *
   * @var string
   */
  public $poolProvisionedIops;
  /**
   * Provisioned throughput of the storage pool in MiB/s. Only relevant if the
   * storage pool type is hyperdisk-balanced or hyperdisk-throughput.
   *
   * @var string
   */
  public $poolProvisionedThroughput;

  /**
   * Size of the storage pool in GiB.
   *
   * @param string $poolProvisionedCapacityGb
   */
  public function setPoolProvisionedCapacityGb($poolProvisionedCapacityGb)
  {
    $this->poolProvisionedCapacityGb = $poolProvisionedCapacityGb;
  }
  /**
   * @return string
   */
  public function getPoolProvisionedCapacityGb()
  {
    return $this->poolProvisionedCapacityGb;
  }
  /**
   * Provisioned IOPS of the storage pool. Only relevant if the storage pool
   * type is hyperdisk-balanced.
   *
   * @param string $poolProvisionedIops
   */
  public function setPoolProvisionedIops($poolProvisionedIops)
  {
    $this->poolProvisionedIops = $poolProvisionedIops;
  }
  /**
   * @return string
   */
  public function getPoolProvisionedIops()
  {
    return $this->poolProvisionedIops;
  }
  /**
   * Provisioned throughput of the storage pool in MiB/s. Only relevant if the
   * storage pool type is hyperdisk-balanced or hyperdisk-throughput.
   *
   * @param string $poolProvisionedThroughput
   */
  public function setPoolProvisionedThroughput($poolProvisionedThroughput)
  {
    $this->poolProvisionedThroughput = $poolProvisionedThroughput;
  }
  /**
   * @return string
   */
  public function getPoolProvisionedThroughput()
  {
    return $this->poolProvisionedThroughput;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(FutureReservationStoragePoolProvisionedCapacity::class, 'Google_Service_Compute_FutureReservationStoragePoolProvisionedCapacity');
