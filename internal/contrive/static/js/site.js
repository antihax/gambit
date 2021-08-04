
function getESJSON(url, df) {
    $.getJSON(url, function (data) {
        data.forEach((row, index) => {
            data[index] = Object.keys(row).reduce((prev, current) =>
                ({ ...prev, [current.replace("gambit.", "")]: row[current][0] }), {})
        });
        df(data);
    });
}

var uuid_count = 0;
function uuid(name) {
    return "O-" + (name == null ? "" : name + "-") + ++uuid_count;
}

function responsivefy(svg) {
    var container = d3.select(svg.node().parentNode),
        width = parseInt(svg.style("width")),
        height = parseInt(svg.style("height")),
        aspect = width / height;

    svg.attr("viewBox", "0 0 " + width + " " + height)
        .attr("perserveAspectRatio", "xMinYMid")
        .call(resize);

    d3.select(window).on("resize." + container.attr("id"), resize);

    function resize() {
        var targetWidth = parseInt(container.style("width"));
        svg.attr("width", targetWidth);
        svg.attr("height", Math.round(targetWidth / aspect));
    }
}