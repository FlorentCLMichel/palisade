/**
 * @file parallel.h This file contains the functionality for parallel operation
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SRC_CORE_LIB_UTILS_PARALLEL_H_
#define SRC_CORE_LIB_UTILS_PARALLEL_H_

#include "omp.h"
//#include <iostream>
namespace lbcrypto {

  class ParallelControls {
    int machineThreads;
  public:
    // @Brief CTOR, enables parallel operations as default
    // Cache the number of machine threads the system reports (can be
    // overridden by environment variables)
    // enable on startup by default
    ParallelControls() {
      machineThreads = omp_get_max_threads();
      Enable();
    }
    // @Brief Enable() enables parallel operation
    void Enable() {
      omp_set_num_threads(machineThreads);
    }
    // @Brief Disable() disables parallel operation
    void Disable() {
      omp_set_num_threads(0);
    }

    int GetMachineThreads() const { return machineThreads; }

    // @Brief returns current number of threads that are usable
    // @return int # threads
    int GetNumThreads() {
      int out, nthreads, tid;
	  	
      // Fork a team of threads giving them their own copies of variables
      //so we can see how many threads we have to work with
#pragma omp parallel private( tid)
      {
	/* Obtain thread number */
	tid = omp_get_thread_num();
	
	/* Only master thread does this */
	if (tid == 0) {
	  nthreads = omp_get_num_threads();
	  out = nthreads;
	}
      }
      //std::cout << "\nNumber of threads = " << out << std::endl;
      return(out);
    }
       
    // @Brief sets number of threads to use (limited by system value)

    void SetNumThreads(int nthreads) {
      //set number of thread, but limit it to the system set
      //number of machine threads... 
      if (nthreads > machineThreads) {
	nthreads = machineThreads;
      }
      omp_set_num_threads(nthreads);
    }
};

extern ParallelControls PalisadeParallelControls;

}

#endif /* SRC_CORE_LIB_UTILS_PARALLEL_H_ */
