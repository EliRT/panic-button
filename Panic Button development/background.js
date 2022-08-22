chrome.runtime.onMessage.addListener(sendTabs);     //creates listener for communication with content script
function sendTabs(request, sender, sendResponse) {

  if (request.msg == "print"){            //prints to console for tests
    console.log(request.content);
  }

  else if (request.msg == "closeTab"){    //closes current tab
    chrome.tabs.query({currentWindow: true ,active: true}, closeTab);
  }
}

function closeTab(currTab){               //closes passed tab from query
  chrome.tabs.remove(currTab[0].id);
}