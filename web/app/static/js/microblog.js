let arrayData;
function populate_table(blog_entries) {
    arrayData = blog_entries
    var data = document.getElementById("user")
    var user = data.dataset.id
    console.log(user);
    var blog = document.getElementById("blog1");
    //Object.keys(blog_entries).reverse()
    Object.keys(blog_entries).forEach(function (i, index) {
        var owner = blog_entries[i][0]
        var element  = blog_entries[i][1];
        console.log(owner.name);
        console.log(element.message);
        console.log(element.date_created);
        console.log(element.date_updated);
        console.log(element.owner_id);
        var entry = document.createElement("div");
        var options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };

        const date1 = new Date(element.date_created);
        date3 = date1.toLocaleString('en-US', {year: 'numeric', month: '2-digit', day: '2-digit'
                                , hour: '2-digit', minute:'2-digit', second: '2-digit'}).replace(',', ''); // remove comma separato
        // console.log(date1)
        const date2 = new Date(element.date_updated);
        date4 = date2.toLocaleString('en-US', {year: 'numeric', month: '2-digit', day: '2-digit'
                                , hour: '2-digit', minute:'2-digit', second: '2-digit'}).replace(',', ''); // remove comma separato
        // ${date2.toLocaleDateString("en-US", options)}

        entry.innerHTML = `
            <div class="tweet" id="blog1">
                <div class="row">
                    <div class="col-md-2 text-center">
                        <div class="col-md-2 text-center">
                            <img class="tw-user-medium rounded-circle" src="${owner.id === element.owner_id ? owner.avatar_url : element.avatar_url}">
                        </div>  
                    </div>
                    <div class="col-md-10" id="datainfo">
                        <div class="row tweet-info" id="id">
                            <div class="col-md-auto">
                                <span class="tweet-username" id="name">${owner.id === element.owner_id ? owner.name : element.name}</span>
                                <span class="tweet-usertag text-muted" id="email">${owner.id === element.owner_id ? owner.email : element.email}</span>
                            </div>
                            <div class="col-md-auto">
                                ${element.date_created === element.date_updated ?`<span class="tweet-date-created" id="date_created">${date3}</span>`:`<span class="tweet-date-updated" id="date_updated">${date4}</span>`}
                            </div>
                            <div class="col tweet-arrow text-muted">
                                <a class="oi oi-arrow-thick-bottom float-right" href="mailto:${owner.email}"></a>
                            </div>
                        </div>
                    <div class="tweet-text" id="text"> 
                        ${element.message}
                    </div>
                    <div class="tweet-media">
                        
                    </div>
                    <div class="row text-muted">
                        <div class="btn-group" id="interact">
                            <span class="oi oi-bullhorn"></span>
                            <span class="oi oi-loop-circular"></span>
                            <span class="oi oi-heart"></span>
                            <span class="oi oi-envelope-open"></span>
                        </div>
                        <div class="btn-group" id="edit">
                            ${user == element.owner_id ?
                            `<span onclick="removeItem(${element.id})" class="oi oi-trash" id="trash"></span>
                            <span onclick="prePopulateForm(${index})" class="oi oi-list" id="edit-2"></span>`
                            :
                            `<a class="dropdown-item" href="javascript:void(0)" onclick="">
                                <i class="fa-solid fa-trash"></i>
                                report
                            </a>`}
                        </div>  
                        

                    </div>
                </div>
            </div>
        
        `;
        blog.appendChild(entry);
    });

    // console.log("error404");
}
//  function updateAuth(userid,ownerid,id) {
//       var data = document.getElementById("user");
//       if (userid == ownerid ) {
//         $.ajax({
//           type : 'POST',
//           url : '/lab11/update',
//           data : {id : id , name : data.dataset.name , email : data.dataset.email , avatar_url : data.dataset.avatar},
//           success : function () {
//             $.getJSON("lab11/BlogEntry", function (i) {
//               refresh_table(i);
//             });
//           }
//         });
//       }
//     }

$(document).ready(function () {
    (function () {
        $.getJSON("lab11/BlogEntry", populate_table);
    })();
});


    // refresh the table after a read update
function refresh_table(blog_entries) {
    // document.getElementById("blog1").innerHTML = "";
    // document.getElementById("blog1").addEventListener("load", populate_table(blog_entries));
    $('#blog1').empty();
    populate_table(blog_entries)
}

$('#add-edit').hide();
$('#nav-tweet-btn').on('click', function(event) {
    event.preventDefault();
    $('#add-edit').toggle();
});

$("#blog-table").submit(function (event) {
    // prevent default html form submission action
    event.preventDefault();
    // pack the inputs into a dictionary
    var formData = {};
    $(":input").each(function () {
        var key = $(this).attr('name');
        var val = $(this).val();


        if (key != 'submit') {
            formData[key] = val;
        }
    });
    // formData['name'] = $("#name").val();
    // formData['email'] = $("#email").val();

    var $form = $(this);
    var url = $form.attr("action");

    $.post(url, formData, function (blog_entries) {
        refresh_table(blog_entries);
        $('#message').val('');
        $('#entryid').val('');
    });
    
});

function prePopulateForm(index) {
    if (!confirm("Are you sure you wanna edit this post?")){
        return false;
    }
    $("#blog-table")[0].reset();
    $("#message").val(arrayData[index][1].message)
    $("#entryid").val(arrayData[index][1].id);
}

function removeItem(id) {
    if (!confirm("Think again before delete the blog!")){
        return false;
    }
    var url = "lab11/remove_contact"
    var formData = {'id':id};
    $.post(url, formData, function (blog_entries){
        refresh_table(blog_entries);
    });
}

function showDropdownMenu(event) {
    var dropdown = event.target.nextElementSibling;
    if (dropdown.style.display === "block") {
      dropdown.style.display = "none";
    } else {
      dropdown.style.display = "block";
    }
    document.addEventListener("click", function(event) {
        if (!event.target.matches('.fa-ellipsis') && !event.target.matches('.tw-user-small')) {
          dropdown.style.display = "none";
        }
      });
  }

function clearForm() {
    $('#blog-table')[0].reset();
    $('#entryid').val('');
}

$("#clear_form").click(function () {
    clearForm();
});


$("#cancel_form").click(function () {
    clearForm();
    $("#add-edit").slideUp('fast');
});
