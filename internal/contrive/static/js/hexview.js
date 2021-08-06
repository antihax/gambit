(function (factory) {
    if (typeof define == 'function' && define.amd)
        define('HexView', ['jquery'], factory)
    else if (typeof exports == 'object')
        module.exports = factory(require('jquery'))
    else if (typeof window == 'object')
        window.HexView = factory(jQuery)
    else this.HexView = factory(jQuery);
}
    ((function ($) {
        $.fn.HexView = function (options) {
            const defaults = {
                bin: "No bin data provided",
                step: 16,
                word_size: 1,
            };
            let parent = this;
            this.on("click", "button", function () {
                switch ($(this).val()) {
                    case "hex":
                        $("div.hex_hexview").css("display", "inline-block");
                        $("div.hex_textview").css("display", "none");
                        break;
                    default:
                        $("div.hex_hexview").css("display", "none");
                        $("div.hex_textview").css("display", "inline-block");
                }
            });

            var cfg = $.extend({}, defaults, options);
            cfg.original_bin = cfg.bin;
            this.empty();
            this.addClass("hex_base");
            return this.filter("div").each((function () {
                let line_data, position = 0;

                $(this).append(`
                <div class='hex_controls'>
                    <button class="hex_mode" value="hex">hex</button>
                    <button class="hex_mode" value="asc">asc</button>
                </div>
                <div class="hex_hexview">
                    <div class='hex_address'></div>
                    <div class='hex_text'></div>
                    <div class='hex_raw'></div>
                </div>                   
                <div class="hex_textview"></div>
                    `);

                $("div.hex_textview").append(cfg.bin);

                while (cfg.bin.length > 0) {
                    line_data = cfg.bin.slice(0, cfg.step)
                    cfg.bin = cfg.bin.slice(cfg.step)

                    $("div.hex_address", this).append(dec_to_hex(position, 1)).append("\n")

                    for (var i = 0; i < line_data.length; i += cfg.word_size) {
                        let num = ""
                        for (var j = 0; j < cfg.word_size; j++)
                            num += hex(line_data.charCodeAt(i + j));
                        $("div.hex_text", this).append(num).append(" ")
                    }
                    $("div.hex_text", this).append("\n")

                    var text = ""
                    for (var i = 0; i < line_data.length; i++) {
                        var c = line_data.charCodeAt(i)

                        if ((c >= 32) && (c <= 126))
                            text = text + line_data.charAt(i)
                        else
                            text = text + "."
                    }

                    position += cfg.step
                    $("div.hex_raw", this).append(text + "\n")
                }
            })), this
        }

        function hex(e) {
            const t = "0123456789ABCDEF";
            return e < 0 && (e = 0), e > 255 && (e = 255),
                t.charAt(Math.floor(e / 16)) + t.charAt(e % 16)
        }

        function dec_to_hex(dec, size = 3) {
            let n = "";
            for (let d = size; d >= 0; d--)
                n += hex(dec >> 8 * d & 255);
            return n
        }
    }))
);