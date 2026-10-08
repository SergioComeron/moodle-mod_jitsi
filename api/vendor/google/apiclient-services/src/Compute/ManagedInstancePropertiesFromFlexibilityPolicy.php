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

class ManagedInstancePropertiesFromFlexibilityPolicy extends \Google\Collection
{
  protected $collection_key = 'disks';
  protected $disksType = AttachedDisk::class;
  protected $disksDataType = 'array';
  /**
   * Output only. The machine type to be used for this instance.
   *
   * @var string
   */
  public $machineType;
  /**
   * Name of the minimum CPU platform to be used by this instance. e.g. 'Intel
   * Ice Lake'.
   *
   * @var string
   */
  public $minCpuPlatform;

  /**
   * List of disks to be attached to the instance.
   *
   * @param AttachedDisk[] $disks
   */
  public function setDisks($disks)
  {
    $this->disks = $disks;
  }
  /**
   * @return AttachedDisk[]
   */
  public function getDisks()
  {
    return $this->disks;
  }
  /**
   * Output only. The machine type to be used for this instance.
   *
   * @param string $machineType
   */
  public function setMachineType($machineType)
  {
    $this->machineType = $machineType;
  }
  /**
   * @return string
   */
  public function getMachineType()
  {
    return $this->machineType;
  }
  /**
   * Name of the minimum CPU platform to be used by this instance. e.g. 'Intel
   * Ice Lake'.
   *
   * @param string $minCpuPlatform
   */
  public function setMinCpuPlatform($minCpuPlatform)
  {
    $this->minCpuPlatform = $minCpuPlatform;
  }
  /**
   * @return string
   */
  public function getMinCpuPlatform()
  {
    return $this->minCpuPlatform;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(ManagedInstancePropertiesFromFlexibilityPolicy::class, 'Google_Service_Compute_ManagedInstancePropertiesFromFlexibilityPolicy');
