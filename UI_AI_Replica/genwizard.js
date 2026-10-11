/* GenWizard page restorer: rearranges the saved snapshot's real DOM into the
 * layout of the live app (templates/Genwizard.png) — light theme, floating
 * header pills (brand + view actions left, Canvas/chatbot + app icons right),
 * centered "How can I help you today?" with the prompt pill below.
 * Runs after pif-client.js so the wired prompt box moves along. */
(function () {
  "use strict";

  function hide(el) {
    if (el) el.style.display = "none";
  }

  function restyle() {
    var root = document.querySelector(".mui-1cdq6zk");
    if (!root) return;

    /* pieces the reference view doesn't show */
    hide(document.querySelector(".mui-147svuf")); // chat history
    hide(document.querySelector(".mui-1jj5x96")); // right panel shell
    hide(document.querySelector(".mui-dz874p")); // dead sidebar backdrop

    /* header: [logo GenWizard | sidebar, new-chat]  ...  [Canvas chatbot | icons] */
    var header = document.createElement("header");
    header.className = "gw-header";

    var leftPill = document.createElement("div");
    leftPill.className = "gw-pill gw-pill-left";
    var brand = document.querySelector(".mui-k0ga8k");
    if (brand) leftPill.appendChild(brand);
    var actions = document.querySelector(".mui-1xhj18k");
    if (actions) leftPill.appendChild(actions);
    header.appendChild(leftPill);

    var rightPill = document.createElement("div");
    rightPill.className = "gw-pill gw-pill-right";
    var ribbon = document.querySelector(".mui-fdc2q");
    if (ribbon) {
      // the saved ribbons are dark-theme SVG wordmarks; the reference shows
      // "Canvas" in dark text and "chatbot" in purple — swap in styled text
      var canvasImg = document.querySelector('button[aria-label="Go to Canvas"] img');
      if (canvasImg) {
        var canvasLabel = document.createElement("span");
        canvasLabel.className = "gw-canvas";
        canvasLabel.textContent = "Canvas";
        canvasImg.replaceWith(canvasLabel);
      }
      var chatbotImg = document.querySelector('button[aria-label="Go to Chatbot"] img');
      if (chatbotImg) {
        var chatbotLabel = document.createElement("span");
        chatbotLabel.className = "gw-chatbot";
        chatbotLabel.textContent = "chatbot";
        chatbotImg.replaceWith(chatbotLabel);
      }
      // flatten: fdc2q wraps each icon in nested MuiBox containers whose lost
      // styling breaks the pill layout — move the buttons up two levels
      Array.prototype.slice.call(ribbon.children).forEach(function (child) {
        Array.prototype.slice.call(child.children).forEach(function (grandchild) {
          rightPill.appendChild(grandchild);
        });
      });
      hide(ribbon);
    }
    header.appendChild(rightPill);

    hide(document.querySelector(".mui-1nuq2xo")); // old dark header row (emptied above)
    root.insertBefore(header, root.firstChild);

    var input = document.querySelector(".mui-1juu494");
    if (input) input.placeholder = "Can you write a poem about the beauty of nature?";
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", restyle);
  } else {
    restyle();
  }
})();
