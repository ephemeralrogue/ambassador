## Contributing

Contributions are welcome, however, there are a few stylistic constraints to
consider. This repo has been entirely rewritten from the original Passport
codebase to remove references to classes and pseudo inheritance-style code,
opting instead to promote a cleaner, more direct, and--quite frankly--more
JavaScript-friendly style of Object Delegation. Furthermore, this project is
Promises-based, with callbacks slowly being removed.

Object Delegation and Promises. If you are unsure how to work with these,
Kyle Simpson has written two very excellent books to get you started, both
in the "You Don't Know JS" series: [this & Object Prototypes](https://www.amazon.com/You-Dont-Know-JS-Prototypes/dp/1491904151) &
[Async & Performance](https://www.amazon.com/You-Dont-Know-JS-Performance/dp/1491904224)

### Tests

The test suite is located in the `test/` directory.  All new features are
expected to have corresponding test cases with complete code coverage.  Patches
that increase test coverage are happily accepted.

Ensure that the test suite passes by executing:

```bash
$ make test
```

Coverage reports can be generated and viewed by executing:

```bash
$ make test-cov
$ make view-cov
```
