.. _rust_coding_guidelines:

Coding Guidelines
=================

This document describes how to write Rust code in the kernel.


Style & formatting
------------------

The code should be formatted using ``rustfmt``. In this way, a person
contributing from time to time to the kernel does not need to learn and
remember one more style guide. More importantly, reviewers and maintainers
do not need to spend time pointing out style issues anymore, and thus
less patch roundtrips may be needed to land a change.

.. note:: Conventions on comments and documentation are not checked by
  ``rustfmt``. Thus those are still needed to be taken care of.

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


Code documentation
------------------

Rust kernel code is not documented like C kernel code (i.e. via kernel-doc).
Instead, the usual system for documenting Rust code is used: the ``rustdoc``
tool, which uses Markdown (a lightweight markup language).

To learn Markdown, there are many guides available out there. For instance,
the one at:

	https://commonmark.org/help/

This is how a well-documented Rust function may look like::

	/// Returns the contained [`Some`] value, consuming the `self` value,
	/// without checking that the value is not [`None`].
	///
	/// # Safety
	///
	/// Calling this method on [`None`] is *[undefined behavior]*.
	///
	/// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
	///
	/// # Examples
	///
	/// ```
	/// let x = Some("air");
	/// assert_eq!(unsafe { x.unwrap_unchecked() }, "air");
	/// ```
	pub unsafe fn unwrap_unchecked(self) -> T {
		match self {
			Some(val) => val,

			// SAFETY: the safety contract must be upheld by the caller.
			None => unsafe { hint::unreachable_unchecked() },
		}
	}

This example showcases a few ``rustdoc`` features and some conventions followed
in the kernel:

  - The first paragraph must be a single sentence briefly describing what
    the documented item does. Further explanations must go in extra paragraphs.

  - Unsafe functions must document their safety preconditions under
    a ``# Safety`` section.

  - While not shown here, if a function may panic, the conditions under which
    that happens must be described under a ``# Panics`` section.

    Please note that panicking should be very rare and used only with a good
    reason. In almost all cases, a fallible approach should be used, typically
    returning a ``Result``.

  - If providing examples of usage would help readers, they must be written in
    a section called ``# Examples``.

  - Rust items (functions, types, constants...) must be linked appropriately
    (``rustdoc`` will create a link automatically).

  - Any ``unsafe`` block must be preceded by a ``// SAFETY:`` comment
    describing why the code inside is sound.

    While sometimes the reason might look trivial and therefore unneeded, writing
    these comments is not just a good way of documenting what has been taken into
    account, but most importantly, it provides a way to know that there are
    no *extra* implicit constraints.

To learn more about how to write documentation for Rust and extra features,
please take a look at the ``rustdoc`` `book`_.

.. _book: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html


Naming
------

Rust kernel code follows the usual Rust naming conventions:

	https://rust-lang.github.io/api-guidelines/naming.html

When existing C concepts (e.g. macros, functions, objects...) are wrapped into
a Rust abstraction, a name as close as reasonably possible to the C side should
be used in order to avoid confusion and to improve readability when switching
back and forth between the C and Rust sides. For instance, macros such as
``pr_info`` from C are named the same in the Rust side.

Having said that, casing should be adjusted to follow the Rust naming
conventions, and namespacing introduced by modules and types should not be
repeated in the item names. For instance, when wrapping constants like:

.. code-block:: c

	#define GPIO_LINE_DIRECTION_IN	0
	#define GPIO_LINE_DIRECTION_OUT	1

The equivalent in Rust may look like (ignoring documentation):

.. code-block:: rust

	pub mod gpio {
	    pub enum LineDirection {
	        In = bindings::GPIO_LINE_DIRECTION_IN as _,
	        Out = bindings::GPIO_LINE_DIRECTION_OUT as _,
	    }
	}

That is, the equivalent of ``GPIO_LINE_DIRECTION_IN`` would be referred to as
``gpio::LineDirection::In``. In particular, it should not be named
``gpio::gpio_line_direction::GPIO_LINE_DIRECTION_IN``.
