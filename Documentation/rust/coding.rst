.. _rust_coding:

Coding
======

This document describes how to write Rust code in the kernel.


Coding style
------------

The code should be formatted using ``rustfmt``. In this way, a person
contributing from time to time to the kernel does not need to learn and
remember one more style guide. More importantly, reviewers and maintainers
do not need to spend time pointing out style issues anymore, and thus
less patch roundtrips may be needed to land a change.

.. note:: Conventions on comments and documentation are not checked by
  ``rustfmt``. Thus those are still needed to be taken care of: please see
  :ref:`Documentation/rust/docs.rst <rust_docs>`.

The default settings of ``rustfmt`` are used. This means the idiomatic Rust
style is followed. For instance, 4 spaces are used for indentation rather
than tabs.

It is convenient to instruct editors/IDEs to format while typing,
when saving or at commit time. However, if for some reason reformatting
the entire kernel Rust sources is needed at some point, the following can be
run::

	make LLVM=1 rustfmt

It is also possible to check if everything is formatted (printing a diff
otherwise), for instance for a CI, with::

	make LLVM=1 rustfmtcheck

Like ``clang-format`` for the rest of the kernel, ``rustfmt`` works on
individual files, and does not require a kernel configuration. Sometimes it may
even work with broken code.


Extra lints
-----------

While ``rustc`` is a very helpful compiler, some extra lints and analyses are
available via ``clippy``, a Rust linter. To enable it, pass ``CLIPPY=1`` to
the same invocation used for compilation, e.g.::

	make LLVM=1 CLIPPY=1

Please note that Clippy may change code generation, thus it should not be
enabled while building a production kernel.


Abstractions vs. bindings
-------------------------

Abstractions are Rust code wrapping kernel functionality from the C side.

In order to use functions and types from the C side, bindings are created.
Bindings are the declarations for Rust of those functions and types from
the C side.

For instance, one may write a ``Mutex`` abstraction in Rust which wraps
a ``struct mutex`` from the C side and calls its functions through the bindings.

Abstractions are not available for all the kernel internal APIs and concepts,
but it is intended that coverage is expanded as time goes on. "Leaf" modules
(e.g. drivers) should not use the C bindings directly. Instead, subsystems
should provide as-safe-as-possible abstractions as needed.


Conditional compilation
-----------------------

Rust code has access to conditional compilation based on the kernel
configuration:

.. code-block:: rust

	#[cfg(CONFIG_X)]       // Enabled               (`y` or `m`)
	#[cfg(CONFIG_X="y")]   // Enabled as a built-in (`y`)
	#[cfg(CONFIG_X="m")]   // Enabled as a module   (`m`)
	#[cfg(not(CONFIG_X))]  // Disabled


Documentation
-------------

Please see :ref:`Documentation/rust/docs.rst <rust_docs>`.
