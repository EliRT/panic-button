let scoreDict = {'techsupport': 0.0, 'alert': 0.45454545454545453, 'pc': 0.5454545454545454, 'security': 0.045454545454545456,
'windows': 0.18181818181818182, 'address': 0.30303030303030304, 'financial': 0.030303030303030304,
'message': 0.4393939393939394, 'email': 0.2878787878787879, 'using': 0.13636363636363635,
'virus': 0.015151515151515152, 'breach': 0.0, 'tracking': 0.13636363636363635, 'carry': 0.030303030303030304,
'communications': 0.0, 'ancient': 0.0, 'result': 0.25757575757575757, 'call': 0.5909090909090909, 'stalkers': 0.0,
'thefts': 0.0, 'administrator': 0.030303030303030304, 'exe': 0.2878787878787879, 'hacked': 0.0,
'logs': 0.12121212121212122, 'services': 0.045454545454545456, 'suspended': 0.045454545454545456,
'restart': 0.18181818181818182, 'situation': 0.030303030303030304, 'attention': 0.19696969696969696, 'duped': 0.0,
'contacting': 0.0, 'webcam': 0.0, 'oops': 0.0, 'passwords': 0.0, 'registry': 0.045454545454545456,
'prevent': 0.5303030303030303, 'technicians': 0.015151515151515152, 'connection': 0.015151515151515152, 'adware': 0.0,
'disabled': 0.48484848484848486, 'block': 0.45454545454545453, 'pop': 0.5909090909090909,
'access': 0.18181818181818182, 'reserved': 0.06060606060606061, 'run': 0.30303030303030304,
'worm': 0.015151515151515152, 'program': 0.10606060606060606, 'frame': 0.5909090909090909, 'live': 0.2878787878787879,
'warning': 0.16666666666666666, 'unknown': 0.15151515151515152, 'wrong': 0.09090909090909091, 'classified': 0.0,
'info': 0.6212121212121212, 'attack': 0.0, 'actions': 0.3181818181818182, 'desk': 0.30303030303030304,
'details': 0.3787878787878788, 'computing': 0.0, 'inject': 0.10606060606060606, 'something': 0.09090909090909091,
'malware': 0.0, 'calling': 0.015151515151515152, 'copyright': 0.015151515151515152, 'especially': 0.0,
'technical': 0.030303030303030304, 'vpn': 0.0, 'follow': 0.22727272727272727, 'harmful': 0.0,
'response': 0.3787878787878788, 'engineering': 0.0, 'anonymous': 0.0, 'significant': 0.0, 'shut': 0.0,
'browsing': 0.07575757575757576, 'location': 0.5454545454545454, 'containing': 0.0, 'dear': 0.21212121212121213,
'installed': 0.015151515151515152, 'visit': 0.2727272727272727, 'current': 0.42424242424242425,
'continue': 0.42424242424242425, 'causing': 0.0, 'caused': 0.0, 'exposed': 0.015151515151515152,
'apply': 0.3484848484848485, 'acts': 0.10606060606060606, 'useful': 0.0, 'warriors': 0.0, 'leaked': 0.0, 'often': 0.0,
'concealed': 0.0, 'reason': 0.16666666666666666, 'tcp': 0.0, 'theft': 0.0, 'social': 0.22727272727272727,
'rights': 0.030303030303030304, 'firewall': 0.0, 'major': 0.030303030303030304, 'disk': 0.0, 'logins': 0.0,
'identity': 0.030303030303030304, 'removed': 0.07575757575757576, 'hard': 0.0, 'locked': 0.16666666666666666,
'cause': 0.21212121212121213, 'viruses': 0.0, 'password': 0.045454545454545456, 'deleted': 0.030303030303030304,
'fix': 0.3787878787878788, 'auto': 0.48484848484848486, 'based form': 0.0, 'trick': 0.0, 'software': 0.0, 'crash': 0.0,
'terms': 0.0, 'tech support': 0.0, 'contact': 0.12121212121212122, 'toll-free': 0.0, 'toll free': 0.015151515151515152,
'error': 0.5454545454545454, 'problem': 0.045454545454545456, 'issue': 0.24242424242424243, 'support': 0.151515};

let usedScore = Array(Object.keys(scoreDict).length).fill(0);
let scamScore = 0.0;

window.onload = isScam();
function isScam() {                 //calculates page scam score
    let domain = window.location.hostname;                          //whitelist
    if ((domain == "twitter.com") || domain == "www.omegle.com"){
        return 0;
    }
    
    let docText = allText();
    let max_weight = 0;
    //chrome.runtime.sendMessage({ content: docText, msg: "print" });

    for (let i = 0; i < Object.keys(scoreDict).length; i++) {       //gets sum of scoreDict values for score normalization
        max_weight += scoreDict[Object.keys(scoreDict)[i]];
    }

    for (let i = 0; i < docText.length; i++) {                      //iterates over web page's text, finds matched from scoreDict and calculates score
        let text = docText[i];
        let textScore = 0;

        for (let j = 0; j < Object.keys(scoreDict).length; j++) {
            let keyWord = Object.keys(scoreDict)[j];

            if ((usedScore[j] < 3) && verifyMatch(keyWord, text, text.search(keyWord))) {
                //chrome.runtime.sendMessage({ content: "match is " + keyWord, msg: "print" });
                //chrome.runtime.sendMessage({ content: "usedscore is " + usedScore[j], msg: "print" });
                usedScore[j]++;

                let new_value = textScore + ((1 / max_weight) * scoreDict[keyWord]);
                textScore = new_value;
            }
        }

        scamScore += textScore;
    }

    //chrome.runtime.sendMessage({ content: usedScore, msg: "print" });
    scamScore = (scamScore / docText.length);

    //chrome.runtime.sendMessage({ content: scamScore, msg: "print" });

    if (scamScore * 100 >= 0.4) {                                   //scam score threshold, alerts user with warning popup when passed
        alertUser();
    }
}

function alertUser(){                                               //injects warning popup into the site
    const urlAcumin = chrome.runtime.getURL('font/Acumin-Variable-Concept.ttf');            //injects custom font
    const urlAcuminBold = chrome.runtime.getURL('font/Acumin-Pro-Condensed-Black.ttf');

    const newFontStyleSheet = document.createElement("style");

    newFontStyleSheet.textContent = `
    @font-face {
        font-family: 'Acumin';
        src: url(${urlAcumin});
    }

    @font-face {
        font-family: 'Acumin Bold';
        src: url(${urlAcuminBold});
    }
    `;

    document.head.appendChild(newFontStyleSheet);

    document.body.style.cursor = "auto";

    let CSS = document.createElement("link");                       //links warning popup css
    CSS.rel = "stylesheet";
    CSS.href = chrome.runtime.getURL('styling/Modal.css');
    document.head.appendChild(CSS);

    let modal = document.createElement("div");                      //injects html elements to create popup
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
    logo.src = chrome.runtime.getURL('images/logo128.png');
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
        chrome.runtime.sendMessage({msg: "closeTab" });
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
}

function getTextElems() {                                           //collects all html text elements of the site
    let textElems = ["title", "p", "span", "h1", "h2", "h3", "h4", "h5", "h6", "br", "strong", "em", "q", "li", "dt", "dd"];
    let docElems = [];
    let neededElems = [];

    for (let i = 0; i < textElems.length; i++) {
        let elems = document.querySelectorAll(textElems[i]);

        for (let j = 0; j < elems.length; j++) {
            docElems.push(elems[j]);
        }
    }

    for (let i = 0; i < docElems.length; i++) {
        let contained = false;

        for (let j = 0; j < docElems.length; j++) {

            if ((contained == false) && (j != i) && (docElems[j].contains(docElems[i]))) {
                contained = true;
            }
        }

        if (contained == false) {
            neededElems.push(docElems[i]);
        }
    }

    return neededElems;
}

function getPageText() {                                            //gets formatted text from site's html text elements
    let neededElems = getTextElems();
    let text = [];

    for (let i = 0; i < neededElems.length; i++) {

        if (!(neededElems[i].innerText === undefined)) {
            text.push(neededElems[i].innerText.toLowerCase().trim());
        }
    }

    return text;
}

function allText() {                                                //collects missed text from other html elements
    let docText = getPageText();
    let moreText = document.body.innerText.split("\n");

    for (let i = 0; i < moreText.length; i++) {
        let contained = false;
        let keyWord = moreText[i].toLowerCase().trim().replace(/[^a-z0-9 -]/gi, "-");

        for (let j = 0; j < docText.length; j++) {
            let text = docText[j].replace(/[^a-z0-9 -]/gi, "-");

            if ((contained == false) && (verifyMatch(keyWord, text, text.search(keyWord)))) {
                contained = true;
            }
        }

        if (contained == false) {
            docText.push(moreText[i].toLowerCase().trim());
        }
    }

    return docText;
}

function verifyMatch(keyWord, text, index) {                        //verifies substring match as a word in the text
    if (index == -1) {
        return false;
    }

    let nextChar = text.charAt(index + keyWord.length);
    let pastChar = text.charAt(index - 1);
    return !(/^[a-zA-Z]+$/.test(nextChar)) && !(/^[a-zA-Z]+$/.test(pastChar));

}