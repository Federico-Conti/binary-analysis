# ELF

The goal of this assignment is to familiarize yourself with the ELF file format.
After unzipping `ELF_files.zip`, you will find several file for your analysis.

Each file hides one *flag*, a string in the format `BASC{...}`, where the content inside the braces is at least eight characters long.
In particular, `BASC{3T0N5}`, which is something you may come across, is not the intended flag for the corresponding file.

In some cases, you can get the corresponding flag by merely running the program.
In others, a more creative approach is required. Note that some ELF files have been
intentionally corrupted; you will first need to identify and understand the
issue before proceeding.

Don't worry if you can't find all the flags. The primary task is to analyze the
files using the tools discussed in lectures. Compare them with standard ELF
files on your system and ask yourself: How do they differ? What is unusual or
out of place?

You are required to write a brief report describing your findings.
For each file, explain how it differs from a standard x86/x64 ELF and
detail the steps you took to discover its flag (if you were successful).
Specify which tools you used and how you used them. If you find it helpful,
include screenshots to better illustrate your workflow.

Your report must be in English. Please use a plain text, Markdown, or PDF
format and avoid proprietary office formats (e.g., .docx, .odt).

To submit your work, add the report to your Git repository, then commit and
push your changes.

