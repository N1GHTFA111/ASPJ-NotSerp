function change_sidebar_color() {
    let element = document.getElementById("page-header");
    if (element.innerText == "Transactions"){
        let sidebar_element_to_change = document.getElementById("home");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "All Users"){
        let sidebar_element_to_change = document.getElementById("all_users");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "All Shipments"){
        let sidebar_element_to_change = document.getElementById("shipments");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Inventory"){
        let sidebar_element_to_change = document.getElementById("inventory");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "Upload New Price List"){
        let sidebar_element_to_change = document.getElementById("price_list");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "All Coupons"){
        let sidebar_element_to_change = document.getElementById("coupons");
        sidebar_element_to_change.classList.add("current");
    }
    else if (element.innerText == "All Feedback"){
        let sidebar_element_to_change = document.getElementById("feedback");
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
    $("#search_users").on("keyup", function(){
        var value = $(this).val().toLowerCase();

        $("#users_table tr").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});

$(document).ready(function(){
    $("#role_selected li a").on("click", function(){
        var txt = $(this).text().toLowerCase();
        $("#users_table tr").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(txt) > -1)
        });
    });
});

$(document).ready(function(){
    $("#search_inventory").on("keyup", function(){
        var value = $(this).val().toLowerCase();

        $("#inventory_items tr").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});

$(document).ready(function(){
    $("#category_selected li a").on("click", function(){
        var txt = $(this).text().toLowerCase();
        $("#inventory_items tr").filter(function(){
            $(this).toggle($(this).text().toLowerCase().indexOf(txt) > -1)
        });
    });
});
