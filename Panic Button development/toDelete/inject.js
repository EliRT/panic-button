alert('NIGGA');
//alert(chrome.windows.getCurrent(true, ['normal']));

chrome.windows.onCreated.addListener(
  forceClose(chrome.windows.getLastFocused()),
  ['popup']
);



//let window_id = window.WINDOW_ID_CURRENT;
//let tab_id = chrome.tabs.getCurrent().id;
//alert(tab_id);
//window.onunload = forceClose();
function forceClose(popup_window) {

    //window_id = chrome.windows.getLastFocused();
    //chrome.windows.remove(window_id);
    chrome.tabs.remove(tab_id);
  }

/*window.onunload = (event) => {
    alert('The page is unloaded');
    chrome.tabs.remove(tab.id);
  };*/