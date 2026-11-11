---
name: client-report-writing
description: Formal pentest report structure delivered to clients, used when compiling accepted findings.
---
# Client Report Writing

The report structure below is generalized from a real pentest report template used for a banking client, with specific branding stripped and only the structure kept. Use your own branding, logo, and colors — do not reuse a previous client's branding.

The report template for each vulnerability is as follows:

## Description

General description of this kind of vulnerability and in which *workflow* of the application it is part.

## Exploitation

Description of each of the exploitation steps

## PoC

Here you can paste your Proof of Concept.

## Risk

Here you can describe risks for the application, its users and the company

## Remediation

Here you can provide vulnerability remediation elements to help the program manager to the report treatment

***

### Markdown Tips

Mardown feature can be used like :

# title 1

## Title 2

### Title 3

#### Title 4

* List
* List 2

A **bold** text
An *italic* text

Link : [This link](http://example.net/)

\*\*PoC Code : \*\*

```language
Code goes here

```

Supported languages are :

* burp
* bash
* css
* html
* http
* java
* javascript
* json
* php
* python
* shell
* xml
* graphql
* ruby
* brainfuck :)
