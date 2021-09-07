#!/bin/bash
echo '<script>'
cat pkg/wasmdemo.js
echo -n 'wasm_bindgen("data:application/wasm;base64,'$(cat pkg/wasmdemo_bg.wasm | base64 -w 0)'")'
cat <<HERE
.then(post_wasm);
</script>
HERE
