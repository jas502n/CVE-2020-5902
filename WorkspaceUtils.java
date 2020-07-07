package com.f5.tmui.locallb.handler.workspace;

import com.f5.form.ShellCommandValidator;
import com.f5.log.F5Logger;
import com.f5.model.db.DBConnection;
import com.f5.tmui.util.FolderUtils;
import com.f5.tmui.util.Syscall;
import com.f5.tmui.util.Syscall.CallException;
import com.f5.tmui.util.Syscall.Result;
import com.f5.util.F5Exception;
import com.f5.util.NLSEngine;
import com.f5.util.SHA1;
import com.f5.util.User;
import com.f5.util.WebUtils;
import com.f5.view.web.pagerenderer.Html;
import com.f5.view.web.pagerenderer.Link;
import com.f5.view.web.pagerenderer.TableRow;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.json.simple.JSONObject;

public class WorkspaceUtils {
   public static final String CHMOD_COMMAND = "/bin/chmod";
   public static final String CHOWN_COMMAND = "/bin/chown";
   public static final String FILE_GROUP = "sdm";
   public static final String FILE_MODE = "664";
   public static final String JSON_CHILDREN = "children";
   public static final String JSON_DIRECTORY = "dir";
   public static final String JSON_FILE = "file";
   private static final String ilxWorkspacesDir = "/var/ilx/workspaces/";
   private static final String pluginsDir = "/var/sdm/plugin_store/plugins/";
   private static final Set whitelistDirSet = new HashSet(Arrays.asList("/var/ilx/workspaces/", "/var/sdm/plugin_store/plugins/"));
   private static final List WHITELISTED_QUERIES = Arrays.asList("locallb.irule.ilx.select_plugin_path");
   private static final List WHITELISTED_TMSH_MODULES = Arrays.asList("ilx");
   private static final int OPERATION_IDX = 0;
   private static final int MODULE_IDX = 2;
   private static final String TMUI_DUBBUF_NAME = "Tmui-Dubbuf";

   public static boolean csrfValidated(String bufForm, String timenow, String bufHeader) {
      return bufHeader != null && bufForm != null && timenow != null && bufForm.equals(SHA1.hash(bufHeader + timenow));
   }

   public static JSONObject runTmshCommand(String command, HttpServletRequest request) {
      F5Logger logger = (F5Logger)F5Logger.getLogger(WorkspaceUtils.class);
      JSONObject resultObject = new JSONObject();
      String output = "";
      String error = "";
      if (!csrfValidated(request.getHeader("_bufvalue"), request.getHeader("_timenow"), request.getHeader("Tmui-Dubbuf"))) {
         logger.warn("Invalid user token - token provided by user is not authorized");
         resultObject.put("output", output);
         resultObject.put("error", NLSEngine.getString("ilx.workspace.error.InvalidUserToken"));
         return resultObject;
      } else {
         if ("POST".equalsIgnoreCase(request.getMethod())) {
            String[] cmdArray = command.split(" ");
            String operation = cmdArray[0];
            String module = cmdArray[2];
            if (!ShellCommandValidator.checkForBadShellCharacters(command) && (operation.equals("create") || operation.equals("delete") || operation.equals("list") || operation.equals("modify")) && WHITELISTED_TMSH_MODULES.contains(module)) {
               try {
                  String[] args = new String[]{command};
                  Result result = Syscall.callElevated(Syscall.TMSH, args);
                  output = result.getOutput();
                  error = result.getError();
               } catch (CallException var11) {
                  logger.error(NLSEngine.getString("ilx.workspace.error.TmshCommandFailed") + ": " + var11.getMessage());
                  error = var11.getMessage();
               }
            } else {
               error = NLSEngine.getString("ilx.workspace.error.RejectedTmshCommand");
            }
         } else {
            error = NLSEngine.getString("ilx.workspace.error.InvalidMethod");
         }

         resultObject.put("output", output);
         resultObject.put("error", error);
         return resultObject;
      }
   }

   private static void listDirectoryRecursive(File dir, JsonArray parent) {
      File[] list = dir.listFiles();
      Arrays.sort(list);
      File[] arr$ = list;
      int len$ = list.length;

      for(int i$ = 0; i$ < len$; ++i$) {
         File file = arr$[i$];
         JsonObject dirObj;
         if (file.isDirectory()) {
            dirObj = new JsonObject();
            dirObj.addProperty("dir", file.getName());
            parent.add(dirObj);
            JsonArray children = new JsonArray();
            dirObj.add("children", children);
            listDirectoryRecursive(file, children);
         } else {
            dirObj = new JsonObject();
            dirObj.addProperty("file", file.getName());
            parent.add(dirObj);
         }
      }

   }

   public static JSONObject listDirectory(String directoryPath) throws Exception {
      JSONObject resultObject = new JSONObject();
      File directory = new File(directoryPath);
      if (directory.exists()) {
         JsonObject listObj = new JsonObject();
         listObj.addProperty("dir", directory.getName());
         JsonArray children = new JsonArray();
         listObj.add("children", children);
         listDirectoryRecursive(directory, children);
         resultObject.put("output", listObj);
      }

      return resultObject;
   }

   public static JSONObject readFile(String fileName) throws FileNotFoundException {
      JSONObject resultObject = new JSONObject();
      File file = new File(fileName);
      StringBuilder fileContents = new StringBuilder((int)file.length());
      Scanner scanner = new Scanner(new BufferedReader(new FileReader(file)));
      String lineSeparator = System.getProperty("line.separator");

      JSONObject var6;
      try {
         while(scanner.hasNextLine()) {
            fileContents.append(scanner.nextLine() + lineSeparator);
         }

         resultObject.put("output", fileContents.toString());
         var6 = resultObject;
      } finally {
         scanner.close();
      }

      return var6;
   }

   public static JSONObject saveFile(HttpServletRequest request) throws IOException {
      F5Logger logger = (F5Logger)F5Logger.getLogger(WorkspaceUtils.class);
      PrintWriter writer = null;
      JSONObject resultObject = new JSONObject();

      label75: {
         JSONObject var4;
         try {
            String content;
            try {
               if (csrfValidated(request.getHeader("_bufvalue"), request.getHeader("_timenow"), request.getHeader("Tmui-Dubbuf"))) {
                  String fileName = WebUtils.getProperty(request, "fileName");
                  content = WebUtils.getProperty(request, "content");
                  writer = new PrintWriter(new FileWriter(fileName));
                  writer.println(content);
                  String[] chmodCmd = new String[]{"/bin/chmod", "664", fileName};
                  Runtime.getRuntime().exec(chmodCmd);
                  String[] chownCmd = new String[]{"/bin/chown", ":sdm", fileName};
                  Runtime.getRuntime().exec(chownCmd);
                  break label75;
               }

               logger.warn("Invalid user token - token provided by user is not authorized");
               resultObject.put("error", NLSEngine.getString("ilx.workspace.error.InvalidUserToken"));
               var4 = resultObject;
            } catch (IOException var12) {
               content = NLSEngine.getString("ilx.workspace.error.ErrorWritingFile") + ": " + var12.getMessage();
               logger.error(content);
               throw var12;
            } catch (SecurityException var13) {
               content = NLSEngine.getString("ilx.workspace.error.ErrorWritingFile") + ": " + var13.getMessage();
               logger.error(content);
               throw var13;
            }
         } finally {
            if (writer != null) {
               writer.close();
            }

         }

         return var4;
      }

      resultObject.put("output", "Success");
      return resultObject;
   }

   public static void addArrayItemsToRow(ArrayList list, TableRow row, String linkBase) {
      Iterator iterator = list.iterator();
      String pluginName = (String)iterator.next();
      Link link = new Link(linkBase + pluginName, FolderUtils.getLeafName(pluginName));

      Link newLink;
      for(Link parentEle = link; iterator.hasNext(); parentEle = newLink) {
         pluginName = (String)iterator.next();
         Html comma = new Html("<span>,</span>");
         parentEle.setChildRowElement(comma);
         newLink = new Link(linkBase + pluginName, FolderUtils.getLeafName(pluginName));
         comma.setChildRowElement(newLink);
      }

      row.addChainedRowElement(link);
   }

   public static String archiveArgPath(String partition, String file) {
      return "/" + partition + "/" + file;
   }

   public static String archiveRealPath(String partition, String file) {
      return "/var/ilx/workspaces/" + partition + "/archive/" + file;
   }

   public static JSONObject dbQuery(String queryName, String objName, String columnName) throws SQLException, F5Exception {
      if (!WHITELISTED_QUERIES.contains(queryName)) {
         throw new F5Exception("Illegal query: " + queryName);
      } else {
         JSONObject resultObject = new JSONObject();

         JSONObject var6;
         try {
            if (!DBConnection.isAllocated()) {
               DBConnection.allocate();
            }

            ResultSet rs = DBConnection.execute(queryName, new Object[]{objName});
            String result = "";
            if (rs != null && rs.next()) {
               result = rs.getString(columnName);
            }

            resultObject.put("output", result);
            var6 = resultObject;
         } catch (SQLException var15) {
            throw var15;
         } finally {
            try {
               if (DBConnection.isAllocated()) {
                  DBConnection.deallocate();
               }
            } catch (SQLException var14) {
               throw var14;
            }

         }

         return var6;
      }
   }

   public static boolean isFileWhitelisted(String fileName) throws IOException {
      F5Logger log = (F5Logger)F5Logger.getLogger(WorkspaceUtils.class);
      boolean isWhitelisted = false;
      File file = new File(fileName);
      String canonFilename = file.getCanonicalPath();
      Path canonPath = Paths.get(canonFilename);
      log.debug("Input filename " + fileName + " has canon name " + canonFilename);
      if (!Files.isDirectory(canonPath.getParent(), new LinkOption[0])) {
         log.debug("Directory for file " + canonFilename + " does not exist; failing");
         throw new FileNotFoundException("Dir path to file " + fileName + " does not exist.");
      } else {
         Path realDirPath = canonPath.getParent().toRealPath();
         Iterator i$ = whitelistDirSet.iterator();

         while(i$.hasNext()) {
            String whitelistDir = (String)i$.next();
            Path whitelistDirPath = Paths.get(whitelistDir);
            log.debug("Checking if " + canonFilename + " lies under directory " + whitelistDir);
            if (realDirPath.startsWith(whitelistDirPath)) {
               log.debug("  > " + canonFilename + " is whitelisted under " + whitelistDir);
               isWhitelisted = true;
               break;
            }
         }

         log.debug(canonFilename + " is " + (isWhitelisted ? "" : "not ") + "a whitelisted file");
         return isWhitelisted;
      }
   }

   public static boolean isUserAuthorized(User user) {
      switch(user.getRawRoleId()) {
      case 0:
      case 20:
      case 100:
      case 510:
         return true;
      default:
         return false;
      }
   }

   public static boolean userCanAccessPartition(User user, String fileName, boolean checkUserPartitionPermission) throws IOException {
      F5Logger log = (F5Logger)F5Logger.getLogger(WorkspaceUtils.class);
      File file = new File(fileName);
      String canonFilename = file.getCanonicalPath();
      Path canonPath = Paths.get(canonFilename);
      log.debug("Input filename " + fileName + " has canon name " + canonFilename);
      String partition = null;
      int delimiterIndex;
      if (canonFilename.startsWith("/var/ilx/workspaces/")) {
         delimiterIndex = canonFilename.indexOf(47, "/var/ilx/workspaces/".length());
         if (delimiterIndex < 0) {
            log.error(canonFilename + " is a file with no partition. Failing.");
            return false;
         }

         partition = canonFilename.substring("/var/ilx/workspaces/".length(), delimiterIndex);
      } else {
         if (!canonFilename.startsWith("/var/sdm/plugin_store/plugins/")) {
            log.error("Filename " + canonFilename + " is not in a whitelisted directory");
            return false;
         }

         delimiterIndex = canonFilename.indexOf(58, "/var/sdm/plugin_store/plugins/".length() + 1);
         if (delimiterIndex < 0) {
            log.error(canonFilename + " is a file with no partition. Failing.");
            return false;
         }

         partition = canonFilename.substring("/var/sdm/plugin_store/plugins/".length() + 1, delimiterIndex);
      }

      List allowedPartitions = user.getAllowedPartitions();
      log.debug(canonFilename + " lies in partition " + partition + "; this is" + (allowedPartitions.contains(partition) ? "" : " not") + " a permitted partition from user's partitions of " + allowedPartitions.toString());
      if (!allowedPartitions.contains(partition)) {
         return false;
      } else if (checkUserPartitionPermission) {
         HashMap allRoles = user.getAllRoles();
         log.debug(user.getUsername() + " has roles " + allRoles.toString());
         int partitionRole = true;
         int partitionRole;
         if (allRoles.containsKey("[All]")) {
            partitionRole = (Integer)allRoles.get("[All]");
         } else {
            if (!allRoles.containsKey(partition)) {
               log.debug(user.getUsername() + " has no role for partition " + partition);
               return false;
            }

            partitionRole = (Integer)allRoles.get(partition);
         }

         log.debug(user.getUsername() + " has role " + User.getRoleName(partitionRole) + " on partition " + partition);
         boolean isSuperAdmin = partitionRole == 0;
         boolean isAdminReadOnly = partitionRole == 20;
         boolean isManager = partitionRole == 100;
         boolean isIRuleManager = partitionRole == 510;
         return isSuperAdmin || isAdminReadOnly || isManager || isIRuleManager;
      } else {
         return true;
      }
   }
}
