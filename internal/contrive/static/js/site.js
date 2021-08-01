
function getESJSON(url, df) {
    $.getJSON(url, function (data) {
        data.forEach((row, index) => {
            data[index] = Object.keys(row).reduce((prev, current) =>
                ({ ...prev, [current.replace("gambit.", "")]: row[current][0] }), {})
        });
        df(data);
    });
}