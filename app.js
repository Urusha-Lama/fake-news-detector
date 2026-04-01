function checkNews() {
    let news = document.getElementById("news").value;

    if(!news.trim()){
        alert("Please enter news");
        return;
    }

    fetch("../backend/predict.php", {
        method: "POST",
        body: new URLSearchParams({news: news})
    })
    .then(res => res.json())   // 🔥 change here
    .then(data => {
        showResult(data);
    });
}