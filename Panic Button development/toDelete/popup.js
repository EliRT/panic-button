var checkboxDict = {};

chrome.runtime.sendMessage({status: "getTabs"});
console.log("asked for tabs!");

chrome.runtime.onMessage.addListener(getTabs);
function getTabs(request, sender, sendResponse) {
  console.log(request.msg);
  let tabDict = request.tabs;
  
  if(Object.keys(tabDict).length > 0){
    checkboxDict = {};

    console.log("tabs are:");
    console.log(tabDict);
    
    let html = '';
    for (let i=0; i<Object.keys(tabDict).length; i++){
      let id = Object.keys(tabDict)[i];
      html += '<input type="checkbox" id=' + id.toString() + ' name="checkbox">';
      html += '<label for=' + id.toString() + '>' + tabDict[id] + '</label> <br>';
      let textId = (22).toString() + id.toString();

      console.log(textId);
      console.log(html);

      document.getElementById("tabList").innerHTML = html;
    
      let checkBox = document.getElementById(id.toString());
      let textForBox = document.getElementById(textId);

      checkboxDict[id] = {box: checkBox, text: textForBox};
    }

    console.log(checkboxDict);
    html ='<p> <button type="button" id="closeTabs">Click me to close the selected tabs!</button> </p>';
    document.getElementById("tabList").innerHTML += html;

    let button = document.getElementById("closeTabs");
    button.addEventListener("click", handleSelected);
  }
}

function handleSelected(){
  let elements = document.getElementsByName("checkbox");

  for(let i=0; i < elements.length; i++){
    console.log(elements[i].id);

    if(elements[i].checked){
      chrome.tabs.remove(parseInt(elements[i].id));
      chrome.runtime.sendMessage({status: "closingTab", tabId: elements[i].id});
    }
  }
}