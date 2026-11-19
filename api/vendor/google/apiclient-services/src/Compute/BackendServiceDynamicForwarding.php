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

class BackendServiceDynamicForwarding extends \Google\Model
{
  protected $forwardProxyType = BackendServiceDynamicForwardingForwardProxy::class;
  protected $forwardProxyDataType = '';
  protected $ipPortSelectionType = BackendServiceDynamicForwardingIpPortSelection::class;
  protected $ipPortSelectionDataType = '';

  /**
   * Dynamic Forwarding Proxy configuration.
   *
   * @param BackendServiceDynamicForwardingForwardProxy $forwardProxy
   */
  public function setForwardProxy(BackendServiceDynamicForwardingForwardProxy $forwardProxy)
  {
    $this->forwardProxy = $forwardProxy;
  }
  /**
   * @return BackendServiceDynamicForwardingForwardProxy
   */
  public function getForwardProxy()
  {
    return $this->forwardProxy;
  }
  /**
   * IP:PORT based dynamic forwarding configuration.
   *
   * @param BackendServiceDynamicForwardingIpPortSelection $ipPortSelection
   */
  public function setIpPortSelection(BackendServiceDynamicForwardingIpPortSelection $ipPortSelection)
  {
    $this->ipPortSelection = $ipPortSelection;
  }
  /**
   * @return BackendServiceDynamicForwardingIpPortSelection
   */
  public function getIpPortSelection()
  {
    return $this->ipPortSelection;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(BackendServiceDynamicForwarding::class, 'Google_Service_Compute_BackendServiceDynamicForwarding');
