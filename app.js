---
layout: compress
# Chirpy v2.2
# https://github.com/cotes2020/jekyll-theme-chirpy
# © 2020 Cotes Chung
# MIT Licensed
---

/* Registering Service Worker */
if('serviceWorker' in navigator) {
  navigator.serviceWorker.register('{{ "/sw.js" | relative_url }}');
};

// window.alert("Hey Bro how are u ?");


let input = prompt('Did you Enjoyed my Blog ? ')
if (input== "yes") {
  alert('Thank You!');
  
}

else{
  alert('No Problem I will Improve');
}


