 # Contributing to PALISADE

* For significant changes, consider starting a discussion by
  contacting the palisade team at PALISADE-crypto.org to plan your
  modifications so that they can be implemented efficiently and in a
  way that doesn't conflict with any other planned future development
  
* Fork the `palisade-development` repository on GitLab
* Clone your new repository or add it as a remote to an existing repository
* Check out the existing `master` branch, then start a new feature branch for
  your work
* When making changes, write code that is consistent with the surrounding code
  (see the [style guidelines](#style-guidelines) below)
* Add tests for any new features that you are implementing to either the
  GoogleTest-based test suite or the Python test suite.
* Add examples that highlight new capabilities, or update existing
  examples to make use of new features.
* As you make changes, commit them to your feature branch
  * Configure Git with your name and e-mail address before making any commits
  * Use descriptive commit messages (summary line of no more than 72 characters,
    followed by a blank line and a more detailed summary, if any)
  * Make related changes in a single commit, and unrelated changes in separate
    commits
  * Make sure that your commits do not include any undesired files, e.g., files
    produced as part of the build process or other temporary files.
  * Use Git's history-rewriting features (i.e., `git rebase -i`; see
    https://help.github.com/articles/about-git-rebase/) to organize your commits
    and squash "fixup" commits and reversions.
  * Do not merge your branch with `master`. If needed, you should occasionally
    rebase your branch
    onto the most recent `HEAD` commit of `master`.
  * Periodically run the test suite (`make testall`) to make sure that your
    changes are not causing any test failures.
* Submit a Pull Request on GitLab. Check the results of the continuous-
  integration tests run using [TBD] and resolve any issues that
  arise.
* Additional discussion of good Git & GitLab workflow is provided at
  http://matplotlib.org/devel/gitwash/development_workflow.html and
  https://docs.scipy.org/doc/numpy-1.15.0/dev/gitwash/development_workflow.html
* PALISADE is licensed under a [BSD
  license](https://gitlab.com/palisade-development/blob/master/License.txt)
  which
  allows others to freely modify the code, and if your Pull Request is accepted,
  then that code will be release under this license as well. The copyright for
  PALISADE is held collectively by the contributors. If you have made a
  significant contribution, please add your name to the `AUTHORS.md` file.

# Style Guidelines

* Try to follow the style of surrounding code, and use variable names that
  follow existing patterns. Pay attention to indentation and spacing.
* Configure your editor to use 4 spaces per indentation level, and **never to
  use tabs**.
* Avoid introducing trailing whitespace
* Limit line lengths to 80 characters when possible
* Write comments to explain non-obvious operations within the code.
* Write Doxygen style comments to define all Classes, Templates, and
  methods (both public, private and protected. Please document all
  input and output data characterisitcs (required lengths of vectors,
  restrictions on combinations of variables) as well as any conditions
  that generate exceptions.

## C++

* All classes, member variables, and methods should have Doxygen-style comments
  (e.g., comment lines starting with `//!` or comment blocks starting with `/*!`)
* Avoid defining non-trivial functions in header files
* Header files should include an 'include guard'
* Protected and private member variable names are generally prefixed with
  `m_`. For most classes, member variables should not be public.
* Class names use `InitialCapsNames`
* Methods use `camelCaseNames`
* Do not indent the contents of namespaces

* Code may make use of most C++11 features. The minimum required
  compiler versions are GCC X.Y and  Clang X.Y.
  
* Avoid manual memory management (i.e. `new` and `delete`), preferring to use
  standard library containers, as well as `std::unique_ptr` and
  `std::shared_ptr` when dynamic allocation is required.
* Portions of Boost which are "header only" may be used. If possible, include
  Boost header files only within .cpp files rather than other header files to
  avoid unnecessary increases in compilation time. Boost should not be added
  to the public interface unless its existence and use is optional. This keeps
  the number of dependencies low for users of PALISADE. In these cases,
  `PALISADE_API_NO_BOOST` should be used to conditionally remove Boost dependencies.
* While PALISADE does not specifically follow these rules, the following style
  guides are useful references for possible style choices and the rationales behind them.
  * The Google C++ Style Guide: https://google.github.io/styleguide/cppguide.html
  * http://geosoft.no/development/cppstyle.html

## Python

* Style generally follows PEP8 (https://www.python.org/dev/peps/pep-0008/)
* Code in `.py` and `.pyx` files needs to be written to work with Python 3
* The minimum Python version that PALISADE supports is Python 3.4, so code
  should only use features added in Python 3.4 or earlier
* Code in the Python examples should be written for Python 3

#Acknowlegement

We would like to Acknowlege the Cantera Project. We have modeled this
document on their examples.