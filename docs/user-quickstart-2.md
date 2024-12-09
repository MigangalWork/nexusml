

# Operating data

## Active tasks
You may want to check your currect active tasks. 
You will recivece a list of all active task you have. 

### Request

**GET** `/tasks`

#### Response

```json
{
  "created_at": "string",
  "created_by": {
    "id": "string",
    "type": "user",
    "uuid": "string"
  },
  "description": "string",
  "icon": {
    "created_at": "string",
    "created_by": {
      "id": "string",
      "type": "user",
      "uuid": "string"
    },
    "download_url": "string",
    "filename": "string",
    "id": "string",
    "size": 0,
    "upload_url": {
      "fields": {},
      "url": "string"
    },
    "uuid": "string"
  },
  "id": "string",
  "max_deployments": 0,
  "modified_at": "string",
  "modified_by": {
    "id": "string",
    "type": "user",
    "uuid": "string"
  },
  "name": "string",
  "num_deployments": 0,
  "organization": "string",
  "space_limit": 0,
  "space_usage": 0,
  "status": {
    "description": "string",
    "details": {},
    "display_name": "string",
    "ended_at": "string",
    "name": "string",
    "prev_status": "string",
    "started_at": "string",
    "state_code": "string",
    "status_code": "string",
    "updated_at": "string"
  },
  "uuid": "string"
}
```

## Delete a task

In order to delete a task just call the DELETE `/tasks/<task_id>`. For security reasons
there is no way to delete all tasks in one call, so you have to delete them one by one.

## Update a task

To update a task, the endpoint 

PUT `/tasks/<task_id>` 

must be called. The only updateble task values here are,
the description, icon and name. The schema can not be updated, in order to update a schema from a task you will
need to create a new task.

## Import and export model

If you are working locally and have a trained model you want to export or import you can do it
using:

GET/POST `/tasks/models`

### GET Request

You can get a list of all models using

**GET** `/tasks/models`

or a specific model data using

**GET** `/tasks/models/<model_id>`

in this case the response will be:
```json
{
  "created_at": "<string>",
  "created_by": {
    "id": "<string>",
    "type": "client",
    "uuid": "<string>"
  },
  "id": "<string>",
  "task_schema": {},
  "uuid": "<string>",
  "version": "<string>",
  "docker_image": {
    "file": {
      "created_at": "<string>",
      "created_by": {
        "id": "<string>",
        "type": "user",
        "uuid": "<string>"
      },
      "filename": "<string>",
      "id": "<string>",
      "size": "<integer>",
      "use_for": {
        "description": "File use: \"ai_model\" | \"input\" | \"output\" | \"metadata\" | \"picture\""
      },
      "uuid": "<string>",
      "download_url": "<string>",
      "type": {
        "description": "File type: \"document\" | \"image\" | \"video\" | \"audio\"",
        "nullable": true
      },
      "upload_url": {
        "url": "<string>",
        "fields": {}
      }
    },
    "id": "<string>",
    "repository": "<string>",
    "tag": "<string>"
  },
  "extra_metadata": {}
}
```
