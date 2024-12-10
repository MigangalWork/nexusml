

# Operating data

## Active tasks
You may want to check your current active tasks. To do this, make the appropriate call, and you will receive a list of all the active tasks you have, providing an overview of their status and details.

### Request
**GET** `/tasks`

### Response

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

For security reasons there is no way to delete all tasks in one call, so you have to delete them one by one.

### Request
In order to delete a task just call the:

DELETE `/tasks/<task_id>`.

Replace `<task_id>` with the ID of the task for which you want to delete.

## Update a task
The only updatable task values are the `description`, `icon`, and `name`. The schema itself cannot be updated directly. If you need to update the schema for a task, you will have to create a new task with the desired schema changes.

## Request
To update a task, call the endpoint:

PUT `/tasks/<task_id>` 

Replace `<task_id>` with the ID of the task for which you want to update.


## Import and Export Model

If you're working locally and need to export or import a trained model, you can do so using the following endpoint:

**GET/POST** `/tasks/models`

### Export model

To retrieve a list of all models, use the following endpoint:

**GET** `/tasks/models`

To fetch data for a specific model, use:

**GET** `/tasks/models/<model_id>`

### Response
In this case, the response will include detailed information about the model, as shown below:

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
      "download_url": "<string>"
    }
  }
}
```

### Import model

To upload a model call the following endpoint:

**POST** `/tasks/models`

You will need to provide the Docker image information, along with details about the training device, training time, and any additional metadata you wish to include.
### Payload

```json
{
  "docker_image": {
    "file": "<string>",
    "id": "<string>",
    "repository": "<string>",
    "tag": "<string>"
  },
  "training_device": "gpu",
  "training_time": "<number>",
  "extra_metadata": {}
}
```