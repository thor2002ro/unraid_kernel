.. _rust_docs:

Docs
====

This document describes how to make the most out of the kernel documentation
for Rust.

Rust kernel code is not documented like C kernel code (i.e. via kernel-doc).
Instead, the usual system for documenting Rust code is used: the ``rustdoc``
tool, which uses Markdown (a lightweight markup language).

To learn Markdown, there are many guides available out there. For instance,
the one at:

	https://commonmark.org/help/


Reading the docs
----------------

The generated HTML docs produced by ``rustdoc`` include integrated search,
linked items (e.g. types, functions, constants), source code, etc.

The generated docs may be read at (TODO: link when in mainline and generated
alongside the rest of the documentation):

	http://kernel.org/

The docs can also be easily generated and read locally. This is quite fast
(same order as compiling the code itself) and no special tools or environment
are needed. This has the added advantage that they will be tailored to
the particular kernel configuration used. To generate them, use the ``rustdoc``
target with the same invocation used for compilation, e.g.::

	make LLVM=1 rustdoc


Writing the docs
----------------

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
