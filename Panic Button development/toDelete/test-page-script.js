let ModalCSS = `
@font-face {
  font-family: Acumin;
  src:  url('font/Acumin-Variable-Concept.ttf');
}

@font-face {
  font-family: Acumin Bold;
  src:  url('font/Acumin-Pro-Condensed-Black.ttf');
}

.panicModal {
  display: flex;
  text-align: center;
  align-items: center;
  justify-content: center;
  position: fixed; /* Stay in place */
  left: 0;
  top: 0;
  z-index: 999999999;
  width: 100vw; /* Full width */
  height: 100vh; /* Full height */
  overflow: auto; /* Enable scroll if needed */
  background-color: rgb(0,0,0); /* Fallback color */
  background-color: rgba(0,0,0,0.3); /* Black w/ opacity */
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.3s ease;
}

.panicModal.show {
opacity: 1;
pointer-events: auto;
}

/* Modal Content/Box */
.panicModalContent {
  margin: auto;
  background-color: #fffdfa;
  padding-top: 0;
  padding-right: 0%;
  padding-left: 0.675%;
  padding-bottom: 0.5%;
  max-width: 100%;
  width: 26vh;
  position: fixed;
  top: 0;
  right: 5%;
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2), 0 6px 20px 0 rgba(0, 0, 0, 0.19);
  border-style: solid;
  border-width: thin;
}

.panicModalContent h1 {
  margin: 0;
  font-family: Acumin Bold;
  font-size: 4vh;
  color: #000000;
}

.panicModalContent p {
  color: #000000;
  font-size: 1.5vh;
  font-family: Acumin;
  margin: 0;
}

.panicModalContent img {
  margin-top: 12%;
  margin-left: 8%;
  opacity: 50%;
  height: 5vh;
  width: 5vh;
}

.panicIgnore {
  background-color: #ffffff;
  color: #000000;
  float: right;
  font-size: 1.7vh;
  border: 1px solid rgb(0, 255, 0);
  border-radius: 10px;
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2), 0 6px 20px 0 rgba(0, 0, 0, 0.19);
  font-family: Acumin;
  margin-right: 0%;
  margin-bottom: 2%;
  margin-top: 1%;
}

.panicIgnore:hover,
.panicIgnore:focus {
  color: #aaa;
  text-decoration: none;
  cursor: pointer;
}

.panicClose {
  background-color: #ffffff;
  color: rgb(0, 0, 0);
  float: right;
  font-size: 1.7vh;
  border: 1px solid rgb(255, 0, 0);
  border-radius: 10px;
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2), 0 6px 20px 0 rgba(0, 0, 0, 0.19);
  font-family: Acumin;
  margin-right: 5%;
  margin-bottom: 2%;
  margin-top: 1%;
}

.panicClose:hover,
.panicClose:focus {
  color: #aaa;
  text-decoration: none;
  cursor: pointer;
}
`;

let CSS = document.createElement("style");
//CSS.rel = "stylesheet";
//CSS.href = "https://drive.google.com/uc?id=1dPpZCrkm7AcVEMCcAizpHCZcGkSukIwA";
CSS.innerHTML += ModalCSS;
document.head.appendChild(CSS);

let modal = document.createElement("div");
modal.id = "myPanicModal";
modal.className = "panicModal";

let modal_content = document.createElement("div");
modal_content.className = "panicModalContent";
modal_content.id = "myPanicModalContent";
modal.appendChild(modal_content);

let top_container = document.createElement("div");
top_container.style.display = "flex";
top_container.id = "panic_top_container";
modal_content.appendChild(top_container); 

let text_container = document.createElement("div");
text_container.id = "panic_text_container";
top_container.appendChild(text_container);

let heading_container = document.createElement("div");
heading_container.style.textAlign = "left";
heading_container.id = "panic_heading_container";
text_container.appendChild(heading_container);

let heading = document.createElement("h1");
heading.textContent = "BE AWARE";
heading_container.appendChild(heading);

let logo = document.createElement("img");
logo.id = "panicLogo";
logo.src = "https://drive.google.com/uc?id=1qKAXtGknf34BTMIV5ZqIcp7oatYeAA5Z"; //https://drive.google.com/uc?id=1qKAXtGknf34BTMIV5ZqIcp7oatYeAA5Z
top_container.appendChild(logo);

let p_container = document.createElement("div");
p_container.style.textAlign = "left";
p_container.id = "panic_p_container";
text_container.appendChild(p_container);

let p = document.createElement("p");
p.innerHTML = "It appears that you are<br>entering a site which is<br>suspected to be a scam!";
p_container.appendChild(p);

let button_container = document.createElement("div");
button_container.style.display = "flex";
button_container.style.justifyContent = "left";
button_container.style.marginTop = "2%";
button_container.style.marginRight = "0";
button_container.id = "panic_button_container";
modal_content.appendChild(button_container);

let closeBtn = document.createElement("button");
closeBtn.classList = "panicClose";
closeBtn.textContent = "Escape scam";
closeBtn.onclick = function (){
  alert("closing!");
}
button_container.appendChild(closeBtn);

let ignoreBtn = document.createElement("button");
ignoreBtn.className = "panicIgnore";
ignoreBtn.textContent = "I trust this site";
ignoreBtn.onclick = function() {
  modal.classList.remove('show');
}
button_container.appendChild(ignoreBtn);

logo.addEventListener('load', function() {document.body.appendChild(modal); modal.classList.add("show")});