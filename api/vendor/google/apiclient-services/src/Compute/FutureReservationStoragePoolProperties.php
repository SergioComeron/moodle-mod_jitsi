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

class FutureReservationStoragePoolProperties extends \Google\Model
{
  protected $requestedExapoolProvisionedCapacityGbType = StoragePoolExapoolProvisionedCapacityGb::class;
  protected $requestedExapoolProvisionedCapacityGbDataType = '';
  protected $requestedStoragePoolProvisionedCapacityType = FutureReservationStoragePoolProvisionedCapacity::class;
  protected $requestedStoragePoolProvisionedCapacityDataType = '';
  /**
   * Type of the storage pool.
   *
   * @var string
   */
  public $storagePoolType;

  /**
   * Requested exapool provisioned capacity in GiB.
   *
   * @param StoragePoolExapoolProvisionedCapacityGb $requestedExapoolProvisionedCapacityGb
   */
  public function setRequestedExapoolProvisionedCapacityGb(StoragePoolExapoolProvisionedCapacityGb $requestedExapoolProvisionedCapacityGb)
  {
    $this->requestedExapoolProvisionedCapacityGb = $requestedExapoolProvisionedCapacityGb;
  }
  /**
   * @return StoragePoolExapoolProvisionedCapacityGb
   */
  public function getRequestedExapoolProvisionedCapacityGb()
  {
    return $this->requestedExapoolProvisionedCapacityGb;
  }
  /**
   * Requested storage pool provisioned capacity.
   *
   * @param FutureReservationStoragePoolProvisionedCapacity $requestedStoragePoolProvisionedCapacity
   */
  public function setRequestedStoragePoolProvisionedCapacity(FutureReservationStoragePoolProvisionedCapacity $requestedStoragePoolProvisionedCapacity)
  {
    $this->requestedStoragePoolProvisionedCapacity = $requestedStoragePoolProvisionedCapacity;
  }
  /**
   * @return FutureReservationStoragePoolProvisionedCapacity
   */
  public function getRequestedStoragePoolProvisionedCapacity()
  {
    return $this->requestedStoragePoolProvisionedCapacity;
  }
  /**
   * Type of the storage pool.
   *
   * @param string $storagePoolType
   */
  public function setStoragePoolType($storagePoolType)
  {
    $this->storagePoolType = $storagePoolType;
  }
  /**
   * @return string
   */
  public function getStoragePoolType()
  {
    return $this->storagePoolType;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(FutureReservationStoragePoolProperties::class, 'Google_Service_Compute_FutureReservationStoragePoolProperties');
