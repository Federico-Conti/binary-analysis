pandoc --output ../binaryanalisys.pdf \
-H ./styles/preamble.tex \
--resource-path=.:media \
--verbose ./src/1-Binary/1.0.md ./src/2-Intel/2.0.md ./src/3-Debug/3.0.md