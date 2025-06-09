function change_sidebar_color() {
    let element = document.getElementById("page-header");
    if (element.innerText == "Home"){
        let sidebar_element_to_change = document.getElementById("home");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Feedback"){
        let sidebar_element_to_change = document.getElementById("contact");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Pending Shipments"){
        let sidebar_element_to_change = document.getElementById("shipments");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Custom Medusa PCs"){
        let sidebar_element_to_change = document.getElementById("computers");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "PC Parts"){
        let sidebar_element_to_change = document.getElementById("parts");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Accessories"){
        let sidebar_element_to_change = document.getElementById("accessories");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Download the latest price list"){
        let sidebar_element_to_change = document.getElementById("pricelist");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Redemption Center"){
        let sidebar_element_to_change = document.getElementById("redeem");
        sidebar_element_to_change.classList.add("current");
        sidebar_element_to_change.classList.remove("active");
    }
    else if (element.innerText == "Your Cart"){
        let sidebar_element_to_change = document.getElementById("cart");
        sidebar_element_to_change.classList.add("current");
    }
    else{
        return true;
    }

    return true;
}

window.onload = function() {
    change_sidebar_color();
};

$(document).ready(function(){
    $("#search_accessories").on("keyup", function(){
        var value = $(this).val().toLowerCase();
        $("#page .items").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});

$(document).ready(function(){
    $("#category_selected li").on("click", function(){
        var txt = $(this).text().toLowerCase();
        console.log(txt);
        $("#page .items").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(txt) > -1)
        });

    });
});

$(document).ready(function(){
    $("#search_parts").on("keyup", function(){
        var value = $(this).val().toLowerCase();
        $("#page_parts .items").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});

$(document).ready(function(){
    $("#part_category_selected li").on("click", function(){
        var txt = $(this).text().toLowerCase();
        console.log(txt);
        $("#page_parts .items").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(txt) > -1)
        });

    });
});