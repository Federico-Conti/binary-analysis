pandoc --output ../binaryanalisys.pdf \
-H ./styles/preamble.tex \
--resource-path=.:media \
--verbose ./src/0.0.md ./src/Binary/1.0.md ./src/Intel/2.0.md ./src/Debug/3.0.md



